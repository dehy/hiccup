// SPDX-License-Identifier: AGPL-3.0-or-later

//! The per-user registry of running instances, and the local transport.
//!
//! Each instance writes `<name>.json` in the registry directory, which says
//! how to reach its control endpoint:
//!
//! - Unix: a socket file, `<name>.sock`, next to it. The directory is `0700`
//!   and the socket `0600`, so other users can neither find nor connect to it.
//! - Windows: a named pipe with a random name, whose DACL grants access only
//!   to its owner and to SYSTEM. Remote clients are rejected.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::API_VERSION;

/// How long a liveness probe waits for an instance to accept.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// A registry entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceRecord {
    /// The instance name.
    pub name: String,
    /// Its process ID.
    pub pid: u32,
    /// The socket path (Unix) or pipe name (Windows).
    pub endpoint: String,
    /// The Hiccup version.
    pub version: String,
    /// The control API version.
    pub api_version: String,
    /// When the instance started, in seconds since the Unix epoch.
    pub started_at: u64,
}

/// Why an instance cannot be selected.
#[derive(Debug, thiserror::Error)]
pub enum SelectError {
    /// No instance is running.
    #[error("no running Hiccup instance; start one with `hiccup serve`")]
    NoInstance,
    /// No instance has this name.
    #[error("no running Hiccup instance named {name:?}{}", running_list(.running))]
    NotFound {
        /// The requested name.
        name: String,
        /// The instances that are running.
        running: Vec<String>,
    },
    /// Several instances run and none was chosen.
    #[error("several Hiccup instances are running ({}); choose one with --instance", .0.join(", "))]
    Ambiguous(Vec<String>),
    /// The registry cannot be read.
    #[error("cannot read the instance registry: {0}")]
    Io(#[from] io::Error),
}

fn running_list(running: &[String]) -> String {
    if running.is_empty() {
        String::new()
    } else {
        format!(" (running: {})", running.join(", "))
    }
}

/// Why an instance cannot be registered.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The name is not `[A-Za-z0-9_-]{1,32}`.
    #[error("invalid instance name {0:?}: use 1 to 32 letters, digits, `-` or `_`")]
    InvalidName(String),
    /// A live instance already has this name.
    #[error(
        "a Hiccup instance named {0:?} is already running; choose another name with --instance"
    )]
    AlreadyRunning(String),
    /// A file or the endpoint cannot be created.
    #[error("cannot register the instance: {0}")]
    Io(#[from] io::Error),
}

/// The registry directory.
#[derive(Clone, Debug)]
pub struct Registry {
    dir: PathBuf,
}

impl Registry {
    /// A registry in `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The default directory: `$XDG_RUNTIME_DIR/hiccup` where there is one,
    /// else `hiccup/run` in the local data directory.
    #[must_use]
    pub fn default_dir() -> Option<PathBuf> {
        dirs::runtime_dir()
            .map(|d| d.join("hiccup"))
            .or_else(|| dirs::data_local_dir().map(|d| d.join("hiccup").join("run")))
    }

    /// The registry directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every registered instance, live or stale, sorted by name.
    ///
    /// # Errors
    ///
    /// Fails if the directory exists but cannot be read, or (on Unix) if
    /// other users can access it: they could plant records pointing to
    /// their own endpoints.
    pub fn records(&self) -> io::Result<Vec<InstanceRecord>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        check_private(&self.dir)?;
        let mut records = Vec::new();
        for entry in entries {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                // A half-written or foreign file is not an instance.
                if let Ok(record) = fs::read(&path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<InstanceRecord>(&b).ok())
                    .ok_or(())
                {
                    records.push(record);
                }
            }
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    /// The instances that accept connections. Stale entries are removed.
    ///
    /// # Errors
    ///
    /// Fails if the directory cannot be read.
    pub async fn live(&self) -> io::Result<Vec<InstanceRecord>> {
        let mut live = Vec::new();
        for record in self.records()? {
            match probe(&record.endpoint).await {
                Probe::Dead => self.remove(&record.name),
                // A busy or slow instance is still running: keep it.
                Probe::Alive | Probe::Unknown => live.push(record),
            }
        }
        Ok(live)
    }

    /// The instance named `name`, or the only running one.
    ///
    /// # Errors
    ///
    /// See [`SelectError`].
    pub async fn select(&self, name: Option<&str>) -> Result<InstanceRecord, SelectError> {
        let mut live = self.live().await?;
        let names = || live.iter().map(|r| r.name.clone()).collect::<Vec<_>>();
        match name {
            Some(name) => match live.iter().position(|r| r.name == name) {
                Some(i) => Ok(live.swap_remove(i)),
                None => Err(SelectError::NotFound {
                    name: name.to_owned(),
                    running: names(),
                }),
            },
            None => match live.len() {
                0 => Err(SelectError::NoInstance),
                1 => Ok(live.remove(0)),
                _ => Err(SelectError::Ambiguous(names())),
            },
        }
    }

    /// Registers an instance named `name` and creates its endpoint. The
    /// registration is removed when the returned value is dropped.
    ///
    /// # Errors
    ///
    /// See [`RegisterError`].
    pub async fn register(&self, name: &str) -> Result<Registration, RegisterError> {
        if !is_valid_name(name) {
            return Err(RegisterError::InvalidName(name.to_owned()));
        }
        create_private_dir(&self.dir)?;
        // Held while the instance runs, and released by the OS if it dies:
        // two instances starting at once cannot both take the name.
        let lock_path = self.dir.join(format!("{name}.lock"));
        let lock = tokio::task::spawn_blocking(move || fs::File::create(lock_path))
            .await
            .map_err(io::Error::other)??;
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(RegisterError::AlreadyRunning(name.to_owned()));
            }
            Err(fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        if let Some(existing) = self.records()?.into_iter().find(|r| r.name == name) {
            if probe(&existing.endpoint).await != Probe::Dead {
                return Err(RegisterError::AlreadyRunning(name.to_owned()));
            }
            self.remove(name);
        }

        let endpoint = self.new_endpoint(name)?;
        let listener = listen(&endpoint)?;
        let record = InstanceRecord {
            name: name.to_owned(),
            pid: std::process::id(),
            endpoint,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: API_VERSION.to_owned(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        };
        write_private(
            &self.record_path(name),
            &serde_json::to_vec_pretty(&record).expect("records serialize"),
        )?;
        Ok(Registration {
            registry: self.clone(),
            record,
            listener: Some(listener),
            _lock: lock,
        })
    }

    fn record_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }

    fn remove(&self, name: &str) {
        let _ = fs::remove_file(self.record_path(name));
        #[cfg(unix)]
        let _ = fs::remove_file(self.dir.join(format!("{name}.sock")));
    }

    #[cfg(unix)]
    #[allow(clippy::unnecessary_wraps)] // Fallible on Windows.
    fn new_endpoint(&self, name: &str) -> io::Result<String> {
        Ok(self
            .dir
            .join(format!("{name}.sock"))
            .to_string_lossy()
            .into_owned())
    }

    #[cfg(windows)]
    fn new_endpoint(&self, name: &str) -> io::Result<String> {
        use ring::rand::{SecureRandom, SystemRandom};
        // A random name: another user cannot create the pipe first.
        let mut nonce = [0u8; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| io::Error::other("no randomness"))?;
        let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!("hiccup-{name}-{nonce}"))
    }
}

/// A registered instance. Dropping it unregisters the instance.
#[derive(Debug)]
pub struct Registration {
    registry: Registry,
    record: InstanceRecord,
    listener: Option<Listener>,
    /// The name's lock, released (after the files are removed) on drop.
    _lock: fs::File,
}

impl Registration {
    /// The registry entry.
    #[must_use]
    pub fn record(&self) -> &InstanceRecord {
        &self.record
    }

    /// Takes the control endpoint's listener (once).
    pub(crate) fn take_listener(&mut self) -> Option<Listener> {
        self.listener.take()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Only our own entry: a new instance may have replaced a stale one.
        let ours = fs::read(self.registry.record_path(&self.record.name))
            .ok()
            .and_then(|b| serde_json::from_slice::<InstanceRecord>(&b).ok())
            .is_some_and(|r| r == self.record);
        if ours {
            drop(self.listener.take());
            self.registry.remove(&self.record.name);
        }
    }
}

fn is_valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    /// It accepted a connection.
    Alive,
    /// Nothing listens there: the instance is gone.
    Dead,
    /// Busy or slow: assume it runs.
    Unknown,
}

/// Checks whether an instance runs at `endpoint`. Only a definite "nothing
/// listens" counts as dead, so that a busy instance is never unregistered.
async fn probe(endpoint: &str) -> Probe {
    match tokio::time::timeout(PROBE_TIMEOUT, connect(endpoint)).await {
        Ok(Ok(_)) => Probe::Alive,
        Ok(Err(e))
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Probe::Dead
        }
        Ok(Err(_)) | Err(_) => Probe::Unknown,
    }
}

/// A control connection.
#[cfg(unix)]
pub(crate) type Stream = tokio::net::UnixStream;
/// A control connection.
#[cfg(windows)]
pub(crate) type Stream = interprocess::local_socket::tokio::Stream;

/// Accepts control connections.
#[derive(Debug)]
pub(crate) struct Listener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(windows)]
    inner: interprocess::local_socket::tokio::Listener,
}

impl Listener {
    pub(crate) async fn accept(&self) -> io::Result<Stream> {
        #[cfg(unix)]
        {
            self.inner.accept().await.map(|(stream, _)| stream)
        }
        #[cfg(windows)]
        {
            use interprocess::local_socket::traits::tokio::Listener as _;
            self.inner.accept().await
        }
    }
}

/// Connects to an instance's control endpoint.
#[cfg(unix)]
pub(crate) async fn connect(endpoint: &str) -> io::Result<Stream> {
    tokio::net::UnixStream::connect(endpoint).await
}

/// Connects to an instance's control endpoint.
#[cfg(windows)]
pub(crate) async fn connect(endpoint: &str) -> io::Result<Stream> {
    use interprocess::local_socket::GenericNamespaced;
    use interprocess::local_socket::tokio::prelude::*;
    Stream::connect(endpoint.to_ns_name::<GenericNamespaced>()?).await
}

#[cfg(unix)]
fn listen(endpoint: &str) -> io::Result<Listener> {
    use std::os::unix::fs::PermissionsExt;
    // `register` found any previous socket dead: replace it.
    match fs::remove_file(endpoint) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let inner = tokio::net::UnixListener::bind(endpoint)?;
    // The 0700 directory already keeps other users out; 0600 is a second
    // barrier should the directory ever be opened up.
    fs::set_permissions(endpoint, fs::Permissions::from_mode(0o600))?;
    Ok(Listener { inner })
}

#[cfg(windows)]
fn listen(endpoint: &str) -> io::Result<Listener> {
    use interprocess::local_socket::tokio::prelude::*;
    use interprocess::local_socket::{GenericNamespaced, ListenerOptions};
    use interprocess::os::windows::local_socket::ListenerOptionsExt;
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;
    // Protected DACL: full access for the pipe's owner and SYSTEM only.
    // Remote clients are rejected by default.
    let sddl = widestring::U16CString::from_str("D:P(A;;GA;;;OW)(A;;GA;;;SY)")
        .map_err(io::Error::other)?;
    let inner = ListenerOptions::new()
        .name(endpoint.to_ns_name::<GenericNamespaced>()?)
        .security_descriptor(SecurityDescriptor::deserialize(&sddl)?)
        .create_tokio()?;
    Ok(Listener { inner })
}

/// Refuses a registry directory that other users can access.
#[cfg(unix)]
fn check_private(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // A readable directory whose group and other bits are clear is ours:
    // another user's 0700 directory could not be read.
    let mode = fs::metadata(dir)?.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible to other users (mode {mode:o}); the instance registry must be \
                 private (0700)",
                dir.display()
            ),
        ))
    }
}

/// Windows: the default directory (in `%LOCALAPPDATA%`) is private to the
/// user; a custom one must be protected by the user.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn check_private(_dir: &Path) -> io::Result<()> {
    Ok(())
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700).create(dir)?;
        // An existing directory may be broader: tighten it.
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    builder.create(dir)
}

fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(contents)?;
    drop(file);
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(is_valid_name("default"));
        assert!(is_valid_name("work-2_b"));
        for bad in ["", "a b", "../x", "x.json", &"a".repeat(33)] {
            assert!(!is_valid_name(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn register_select_and_unregister() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::new(dir.path().join("run"));
        assert!(matches!(
            registry.select(None).await,
            Err(SelectError::NoInstance)
        ));

        let a = registry.register("a").await.unwrap();
        assert_eq!(registry.select(None).await.unwrap().name, "a");
        assert!(matches!(
            registry.register("a").await,
            Err(RegisterError::AlreadyRunning(_))
        ));
        let b = registry.register("b").await.unwrap();
        assert!(matches!(
            registry.select(None).await,
            Err(SelectError::Ambiguous(names)) if names == ["a", "b"]
        ));
        assert_eq!(registry.select(Some("b")).await.unwrap(), *b.record());
        assert!(matches!(
            registry.select(Some("c")).await,
            Err(SelectError::NotFound { running, .. }) if running == ["a", "b"]
        ));

        drop(a);
        assert_eq!(registry.select(None).await.unwrap().name, "b");
        drop(b);
        assert!(registry.records().unwrap().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn instances_starting_together_get_one_name() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::new(dir.path().join("run"));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let registry = registry.clone();
                tokio::spawn(async move { registry.register("x").await })
            })
            .collect();
        let mut registered = Vec::new();
        for task in tasks {
            match task.await.unwrap() {
                Ok(r) => registered.push(r),
                Err(RegisterError::AlreadyRunning(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
        assert_eq!(registered.len(), 1);
        assert_eq!(
            registry.live().await.unwrap(),
            [registered[0].record().clone()]
        );
    }

    #[tokio::test]
    async fn stale_entries_are_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::new(dir.path());
        let stale = registry.register("x").await.unwrap();
        // Simulate a crash: the endpoint and the lock are gone, the record
        // remains.
        let record = fs::read(registry.record_path("x")).unwrap();
        drop(stale);
        fs::write(registry.record_path("x"), record).unwrap();
        assert_eq!(registry.records().unwrap().len(), 1);
        assert!(registry.live().await.unwrap().is_empty());
        assert!(registry.records().unwrap().is_empty(), "cleaned up");
        let _again = registry.register("x").await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_registry_others_can_access_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::new(dir.path().join("run"));
        let _reg = registry.register("x").await.unwrap();
        fs::set_permissions(registry.dir(), fs::Permissions::from_mode(0o755)).unwrap();
        let err = registry.records().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(matches!(
            registry.select(None).await,
            Err(SelectError::Io(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        let registry = Registry::new(&run);
        let reg = registry.register("p").await.unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&run), 0o700);
        assert_eq!(mode(&run.join("p.json")), 0o600);
        assert_eq!(mode(Path::new(&reg.record().endpoint)), 0o600);
    }
}
