// SPDX-License-Identifier: AGPL-3.0-or-later

//! Project and traffic history persistence (SQLite).
//!
//! A project file (`.hiccup`) is a SQLite database. Each exchange's metadata
//! is a row of `exchanges`; its raw messages are rows of `blobs`, so listing
//! history never reads them.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hiccup_proxy::{Exchange, Modification, Scheme, Scope, ScopeTarget};
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};

#[cfg(windows)]
mod owner;

/// Schema migrations, in order. The database's `user_version` counts those
/// applied. Never edit one that has shipped: append a new one.
const MIGRATIONS: &[&str] = &[
    "
    CREATE TABLE blobs (
        id INTEGER PRIMARY KEY,
        data BLOB NOT NULL
    );
    CREATE TABLE exchanges (
        id INTEGER PRIMARY KEY,
        started_ms INTEGER NOT NULL,
        duration_ms INTEGER NOT NULL,
        client TEXT NOT NULL,
        upstream TEXT NOT NULL,
        host TEXT NOT NULL COLLATE NOCASE,
        tls INTEGER NOT NULL,
        method TEXT NOT NULL,
        target TEXT NOT NULL,
        status INTEGER,
        mime TEXT,
        request_size INTEGER NOT NULL,
        response_size INTEGER,
        request_edited INTEGER NOT NULL,
        response_edited INTEGER NOT NULL,
        error TEXT,
        -- The request as received; as forwarded, when it differs.
        request_blob INTEGER NOT NULL REFERENCES blobs(id),
        forwarded_blob INTEGER REFERENCES blobs(id),
        -- Interim (1xx) responses, concatenated.
        interim_blob INTEGER REFERENCES blobs(id),
        -- The response as received; as delivered, when the user edited it.
        response_blob INTEGER REFERENCES blobs(id),
        delivered_blob INTEGER REFERENCES blobs(id)
    );
",
    "
    -- The response blob holds only the start of the body.
    ALTER TABLE exchanges ADD COLUMN response_truncated INTEGER NOT NULL DEFAULT 0;
",
];

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// The project file cannot be created or made private.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The project was written by a newer Hiccup.
    #[error("the project uses schema version {0}, newer than this Hiccup supports")]
    TooNew(usize),
    /// The project's location would let another user swap or read it.
    #[error("refusing {path}: {reason}")]
    Unsafe {
        /// The project path.
        path: String,
        /// Why.
        reason: &'static str,
    },
}

/// Which exchanges to list. Every criterion set must match.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    /// The host, exactly (ignoring case).
    pub host: Option<String>,
    /// The request method, exactly.
    pub method: Option<String>,
    /// The response status.
    pub status: Option<u16>,
    /// A prefix of the response's media type: `image/` matches `image/png`.
    pub mime: Option<String>,
    /// Bytes found in the request or the response (as received, forwarded
    /// or delivered). Case-sensitive.
    // shortcut: a full scan of every message (~25 ms per 20 MB); add an index
    // (e.g. FTS5 on decoded text) when projects get large.
    pub search: Option<Vec<u8>>,
    /// Only exchanges in this scope.
    pub scope: Option<Scope>,
}

/// One exchange, without its messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Its ID: higher is newer.
    pub id: i64,
    /// When the request was received in full (millisecond precision).
    pub started: SystemTime,
    /// How long the exchange took (millisecond precision).
    pub duration: Duration,
    /// The client's address.
    pub client: String,
    /// The upstream `host:port`.
    pub upstream: String,
    /// The upstream host.
    pub host: String,
    /// Whether it was decrypted from an intercepted TLS tunnel.
    pub tls: bool,
    /// The request method.
    pub method: String,
    /// The request target, as received.
    pub target: String,
    /// The response status, if a response arrived.
    pub status: Option<u16>,
    /// The response's media type, lowercase, without parameters.
    pub mime: Option<String>,
    /// Size of the request as received, in bytes.
    pub request_size: u64,
    /// Size of the response as kept, in bytes.
    pub response_size: Option<u64>,
    /// Whether only the start of the response body was kept (it was relayed
    /// in full).
    pub response_truncated: bool,
    /// Whether the user edited the request in the intercept queue.
    pub request_edited: bool,
    /// Whether the user edited the response in the intercept queue.
    pub response_edited: bool,
    /// Why the exchange failed, if it did.
    pub error: Option<String>,
}

/// One exchange, with its raw messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The metadata.
    pub summary: Summary,
    /// The request exactly as received.
    pub received: Bytes,
    /// The bytes forwarded upstream.
    pub forwarded: Bytes,
    /// Interim (1xx) responses, concatenated; empty if none.
    pub interim: Bytes,
    /// The response exactly as received, if one arrived.
    pub response: Option<Bytes>,
    /// The bytes sent to the client instead, when the user edited them.
    pub delivered: Option<Bytes>,
}

/// A project's history.
pub struct Store {
    db: Connection,
}

impl Store {
    /// Opens the project file at `path`, creating it if needed, and brings
    /// its schema up to date.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be created or opened, is not a Hiccup
    /// project, or was written by a newer Hiccup.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // SQLite refuses a link anywhere in the path (`NOFOLLOW` below), and
        // directories are often links (`/tmp` on macOS): resolve those.
        #[cfg(unix)]
        let path = &resolve_dir(path)?;
        #[cfg(unix)]
        check_location(path)?;
        // History holds credentials: a new project is readable by its owner
        // only. SQLite gives its -wal and -shm files the same mode.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(
            std::fs::OpenOptions::new().write(true).create(true),
            0o600,
        )
        .open(path)?;
        // An existing project (restored, copied, or someone else's) keeps
        // its mode: tighten it too. Fails on a file we do not own.
        #[cfg(unix)]
        restrict(path)?;
        // Windows: the DACL is set after SQLite opens the file (it creates
        // -wal and -shm), so a file planted by another user, who stays its
        // owner, must be refused before anything is written to it.
        #[cfg(windows)]
        {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)?;
            if !owner::is_ours(path)? {
                return Err(StoreError::Unsafe {
                    path: path.display().to_string(),
                    reason: "another user owns it",
                });
            }
        }
        // A symbolic link swapped in since the check is refused here.
        let mut db = Connection::open_with_flags(
            path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        // With WAL, NORMAL survives application crashes; only a power loss
        // can lose the last few exchanges.
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.pragma_update(None, "foreign_keys", true)?;
        migrate(&mut db)?;
        #[cfg(windows)]
        restrict(path)?;
        Ok(Self { db })
    }

    /// Records an exchange. Returns its ID.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does (for example, the disk is full).
    pub fn insert(&mut self, exchange: &Exchange) -> Result<i64, StoreError> {
        let tx = self.db.transaction()?;
        let blob = |data: &[u8]| -> rusqlite::Result<i64> {
            tx.prepare_cached("INSERT INTO blobs (data) VALUES (?1)")?
                .execute([data])?;
            Ok(tx.last_insert_rowid())
        };
        let received = exchange.received.to_bytes();
        let response = exchange
            .response
            .as_ref()
            .map(hiccup_http::Response::to_bytes);
        let interim: Vec<u8> = exchange.interim.iter().flat_map(|r| r.to_bytes()).collect();
        let request_blob = blob(&received)?;
        let forwarded_blob = (exchange.forwarded != received)
            .then(|| blob(&exchange.forwarded))
            .transpose()?;
        let interim_blob = (!interim.is_empty()).then(|| blob(&interim)).transpose()?;
        let response_blob = response.as_deref().map(blob).transpose()?;
        let delivered_blob = exchange.delivered.as_deref().map(blob).transpose()?;

        let head = exchange.received.head();
        let edited = |m: Modification| exchange.modifications.contains(&m);
        tx.prepare_cached(
            "INSERT INTO exchanges (started_ms, duration_ms, client, upstream, host, tls, method,
                 target, status, mime, request_size, response_size, request_edited,
                 response_edited, error, request_blob, forwarded_blob, interim_blob,
                 response_blob, delivered_blob, response_truncated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                 ?18, ?19, ?20, ?21)",
        )?
        .execute(params![
            millis(
                exchange
                    .started
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
            ),
            millis(exchange.duration),
            exchange.client.to_string(),
            exchange.upstream,
            host(&exchange.upstream),
            exchange.tls,
            String::from_utf8_lossy(head.method()),
            String::from_utf8_lossy(head.target()),
            exchange
                .response
                .as_ref()
                .and_then(|r| r.head().status_code()),
            exchange.response.as_ref().and_then(mime),
            received.len(),
            response.as_ref().map(Vec::len),
            edited(Modification::RequestEdited),
            edited(Modification::ResponseEdited),
            exchange.error,
            request_blob,
            forwarded_blob,
            interim_blob,
            response_blob,
            delivered_blob,
            exchange.response_truncated,
        ])?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Lists matching exchanges, newest first: at most `limit`, older than
    /// `before` (an ID from the previous page) if given.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn list(
        &self,
        filter: &Filter,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<Summary>, StoreError> {
        // The scope is Rust code: SQLite calls it per row. Registered on
        // every call, since the scope changes.
        let scope = filter.scope.clone();
        self.db.create_scalar_function(
            "in_scope",
            4,
            FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
            move |ctx| {
                let Some(scope) = &scope else { return Ok(true) };
                let tls: bool = ctx.get(0)?;
                let (host, upstream, target): (String, String, String) =
                    (ctx.get(1)?, ctx.get(2)?, ctx.get(3)?);
                let port = upstream
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse().ok())
                    .unwrap_or(if tls { 443 } else { 80 });
                Ok(scope.contains(&ScopeTarget {
                    scheme: if tls { Scheme::Https } else { Scheme::Http },
                    host: &host,
                    port,
                    path: &target,
                }))
            },
        )?;
        let mut query = self.db.prepare_cached(&format!(
            "SELECT {SUMMARY} FROM exchanges e
             WHERE (?1 IS NULL OR e.id < ?1)
               AND (?2 IS NULL OR e.host = ?2)
               AND (?3 IS NULL OR e.method = ?3)
               AND (?4 IS NULL OR e.status = ?4)
               AND (?5 IS NULL OR substr(e.mime, 1, length(?5)) = ?5)
               AND (?6 IS NULL OR EXISTS (
                   SELECT 1 FROM blobs b
                   WHERE b.id IN (e.request_blob, e.forwarded_blob, e.response_blob,
                                  e.delivered_blob)
                     AND instr(b.data, ?6) > 0))
               AND (NOT ?8 OR in_scope(e.tls, e.host, e.upstream, e.target))
             ORDER BY e.id DESC
             LIMIT ?7"
        ))?;
        let rows = query.query_map(
            params![
                before,
                filter.host,
                filter.method,
                filter.status,
                filter.mime.as_deref().map(str::to_ascii_lowercase),
                filter.search,
                limit,
                filter.scope.is_some(),
            ],
            summary,
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// One exchange with its messages.
    ///
    /// # Errors
    ///
    /// Fails if SQLite does.
    pub fn get(&self, id: i64) -> Result<Option<Record>, StoreError> {
        let blob = "(SELECT data FROM blobs WHERE id = ";
        let record = self
            .db
            .prepare_cached(&format!(
                "SELECT {SUMMARY},
                     {blob}e.request_blob), {blob}e.forwarded_blob), {blob}e.interim_blob),
                     {blob}e.response_blob), {blob}e.delivered_blob)
                 FROM exchanges e WHERE e.id = ?1"
            ))?
            .query_row([id], |row| {
                let bytes = |i: usize| -> rusqlite::Result<Option<Bytes>> {
                    Ok(row.get::<_, Option<Vec<u8>>>(i)?.map(Bytes::from))
                };
                let received = bytes(17)?.unwrap_or_default();
                Ok(Record {
                    summary: summary(row)?,
                    forwarded: bytes(18)?.unwrap_or_else(|| received.clone()),
                    received,
                    interim: bytes(19)?.unwrap_or_default(),
                    response: bytes(20)?,
                    delivered: bytes(21)?,
                })
            })
            .optional()?;
        Ok(record)
    }
}

/// The columns [`summary`] reads, in order.
const SUMMARY: &str = "e.id, e.started_ms, e.duration_ms, e.client, e.upstream, e.host, e.tls,
    e.method, e.target, e.status, e.mime, e.request_size, e.response_size, e.response_truncated,
    e.request_edited, e.response_edited, e.error";

fn summary(row: &Row<'_>) -> rusqlite::Result<Summary> {
    let ms = |i| row.get::<_, u64>(i).map(Duration::from_millis);
    Ok(Summary {
        id: row.get(0)?,
        started: UNIX_EPOCH + ms(1)?,
        duration: ms(2)?,
        client: row.get(3)?,
        upstream: row.get(4)?,
        host: row.get(5)?,
        tls: row.get(6)?,
        method: row.get(7)?,
        target: row.get(8)?,
        status: row.get(9)?,
        mime: row.get(10)?,
        request_size: row.get(11)?,
        response_size: row.get(12)?,
        response_truncated: row.get(13)?,
        request_edited: row.get(14)?,
        response_edited: row.get(15)?,
        error: row.get(16)?,
    })
}

fn migrate(db: &mut Connection) -> Result<(), StoreError> {
    let version: usize = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > MIGRATIONS.len() {
        return Err(StoreError::TooNew(version));
    }
    let tx = db.transaction()?;
    for (applied, sql) in MIGRATIONS.iter().enumerate().skip(version) {
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", applied + 1)?;
    }
    tx.commit()?;
    Ok(())
}

/// `path` with its directory's symbolic links resolved; the file name is
/// kept as given.
#[cfg(unix)]
fn resolve_dir(path: &Path) -> std::io::Result<std::path::PathBuf> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a file path"))?;
    Ok(dir.canonicalize()?.join(name))
}

/// Refuses a project that another user could swap between our checks and
/// SQLite opening it: a symbolic link, or in a directory others can write
/// to (unless it is sticky, like `/tmp`: others cannot rename or delete our
/// files there, and a file they create first fails `restrict`).
#[cfg(unix)]
fn check_location(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    let unsafe_ = |reason| StoreError::Unsafe {
        path: path.display().to_string(),
        reason,
    };
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(unsafe_("it is a symbolic link; open the file it points to"));
    }
    let dir = path.parent().expect("resolved: has a directory");
    let mode = std::fs::metadata(dir)?.permissions().mode();
    let sticky = mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !sticky {
        return Err(unsafe_(
            "other users can write to its directory, and could replace it",
        ));
    }
    Ok(())
}

/// Makes the project and any leftover -wal / -shm files `0600`.
#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        match std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {}
            result => result?,
        }
    }
    Ok(())
}

/// The directory's ACL is not checked (unlike Unix's `check_location`): a
/// project in a directory other users can write to is the user's call.
/// Makes the project's files private: drops what they inherit from their
/// directory (e.g. `Users`) and grants their owner and `SYSTEM`. What is
/// left besides is the creating token's default (owner, `SYSTEM`,
/// administrators). SQLite creates its -wal and -shm files anew, so this runs
/// on every open, once they exist.
// shortcut: runs the built-in icacls (no `unsafe` for the Win32 security API);
// set the DACL directly if opening a project ever needs to be faster.
#[cfg(windows)]
fn restrict(path: &Path) -> std::io::Result<()> {
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let icacls = Path::new(&system).join(r"System32\icacls.exe");
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        if !Path::new(&file).exists() {
            continue;
        }
        // OWNER RIGHTS and SYSTEM, as SIDs: account names are localized.
        let output = std::process::Command::new(&icacls)
            .arg(&file)
            .args(["/inheritance:r", "/grant:r", "*S-1-3-4:F", "*S-1-5-18:F"])
            .output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "icacls failed on {}: {}",
                Path::new(&file).display(),
                String::from_utf8_lossy(&output.stdout).trim()
            )));
        }
    }
    Ok(())
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The host of a `host:port` (an IPv6 address loses its brackets).
fn host(upstream: &str) -> &str {
    let host = upstream.rsplit_once(':').map_or(upstream, |(h, _)| h);
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// The media type of a response, lowercase, without parameters.
fn mime(response: &hiccup_http::Response) -> Option<String> {
    let value = response.head().get("content-type")?.value_unfolded();
    let value = String::from_utf8_lossy(&value);
    let mime = value.split(';').next()?.trim().to_ascii_lowercase();
    (!mime.is_empty()).then_some(mime)
}
