// SPDX-License-Identifier: AGPL-3.0-or-later

//! History storage: exact bytes, filters, pages, and the 10k benchmark.

use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use hiccup_http::{Limits, Request, Response};
use hiccup_proxy::{Exchange, Modification};
use hiccup_store::{Filter, Store, StoreError};

fn exchange(upstream: &str, request: &[u8], response: Option<&[u8]>) -> Exchange {
    let limits = Limits::default();
    let received = Request::parse(request, &limits, true).unwrap().unwrap();
    let response = response.map(|r| {
        Response::parse(r, received.head().method(), &limits, true)
            .unwrap()
            .unwrap()
    });
    Exchange {
        started: SystemTime::now(),
        duration: Duration::from_millis(12),
        client: "127.0.0.1:5000".parse().unwrap(),
        upstream: upstream.to_owned(),
        tls: false,
        forwarded: Bytes::copy_from_slice(request),
        received,
        modifications: Vec::new(),
        interim: Vec::new(),
        response,
        delivered: None,
        error: None,
    }
}

const GET: &[u8] = b"GET /a?q=1 HTTP/1.1\r\nHost: a.test\r\n\r\n";
const OK_HTML: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: Text/HTML; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello";

#[test]
fn exact_bytes_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.hiccup");
    let mut e = exchange("a.test:80", GET, Some(OK_HTML));
    e.forwarded = Bytes::from_static(b"GET /edited HTTP/1.1\r\n\r\n");
    e.delivered = Some(Bytes::from_static(b"HTTP/1.1 418 Teapot\r\n\r\n"));
    e.modifications = vec![Modification::RequestEdited, Modification::ResponseEdited];
    let id = Store::open(&path).unwrap().insert(&e).unwrap();

    let store = Store::open(&path).unwrap();
    let r = store.get(id).unwrap().unwrap();
    assert_eq!(r.received, GET);
    assert_eq!(r.forwarded, e.forwarded);
    assert_eq!(r.response.as_deref(), Some(OK_HTML));
    assert_eq!(r.delivered, e.delivered);
    assert!(r.interim.is_empty());
    let s = &r.summary;
    assert_eq!((s.method.as_str(), s.target.as_str()), ("GET", "/a?q=1"));
    assert_eq!((s.host.as_str(), s.status), ("a.test", Some(200)));
    assert_eq!(s.mime.as_deref(), Some("text/html"));
    assert_eq!(s.duration, Duration::from_millis(12));
    assert!(s.request_edited && s.response_edited);
    assert_eq!(
        store.list(&Filter::default(), None, 10).unwrap(),
        [r.summary]
    );
    assert!(store.get(id + 1).unwrap().is_none());
}

#[test]
fn unchanged_and_failed_exchanges() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("p.hiccup")).unwrap();
    let mut e = exchange("[::1]:8080", GET, None);
    e.error = Some("refused".into());
    let id = store.insert(&e).unwrap();
    let r = store.get(id).unwrap().unwrap();
    assert_eq!(
        r.forwarded, r.received,
        "stored once, read back as forwarded"
    );
    assert_eq!(r.summary.host, "::1");
    assert_eq!((r.response, r.summary.status), (None, None));
    assert_eq!(r.summary.error.as_deref(), Some("refused"));
}

#[test]
fn filters_and_pages() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("p.hiccup")).unwrap();
    let post = b"POST /login HTTP/1.1\r\nContent-Length: 8\r\n\r\npw=s3cr3";
    let png = b"HTTP/1.1 404 Not Found\r\nContent-Type: image/png\r\nContent-Length: 0\r\n\r\n";
    let a = store
        .insert(&exchange("a.test:80", GET, Some(OK_HTML)))
        .unwrap();
    let b = store
        .insert(&exchange("B.test:443", post, Some(png)))
        .unwrap();
    let c = store.insert(&exchange("a.test:80", post, None)).unwrap();

    let ids = |f: Filter| -> Vec<i64> {
        let list = store.list(&f, None, 10).unwrap();
        list.iter().map(|s| s.id).collect()
    };
    assert_eq!(ids(Filter::default()), [c, b, a], "newest first");
    let host = |h: &str| Filter {
        host: Some(h.into()),
        ..Filter::default()
    };
    assert_eq!(ids(host("a.TEST")), [c, a], "hosts ignore case");
    let method = Filter {
        method: Some("POST".into()),
        ..Filter::default()
    };
    assert_eq!(ids(method), [c, b]);
    assert_eq!(
        ids(Filter {
            status: Some(404),
            ..Filter::default()
        }),
        [b]
    );
    assert_eq!(
        ids(Filter {
            mime: Some("IMAGE/".into()),
            ..Filter::default()
        }),
        [b]
    );
    let search = |s: &[u8]| Filter {
        search: Some(s.to_vec()),
        ..Filter::default()
    };
    assert_eq!(ids(search(b"s3cr3")), [c, b], "request bodies");
    assert_eq!(ids(search(b"hello")), [a], "response bodies");
    assert_eq!(ids(search(b"HELLO")), Vec::<i64>::new());

    let page = store.list(&Filter::default(), None, 2).unwrap();
    assert_eq!(page.len(), 2);
    let next = store.list(&Filter::default(), Some(page[1].id), 2).unwrap();
    assert_eq!(next.iter().map(|s| s.id).collect::<Vec<_>>(), [a]);
}

#[cfg(unix)]
#[test]
fn a_new_project_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.hiccup");
    let mut store = Store::open(&path).unwrap();
    store.insert(&exchange("a.test:80", GET, None)).unwrap();
    for file in ["p.hiccup", "p.hiccup-wal", "p.hiccup-shm"] {
        let mode = std::fs::metadata(dir.path().join(file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }
}

#[cfg(windows)]
#[test]
fn a_new_project_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.hiccup");
    let mut store = Store::open(&path).unwrap();
    store.insert(&exchange("a.test:80", GET, None)).unwrap();
    for file in ["p.hiccup", "p.hiccup-wal", "p.hiccup-shm"] {
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-Acl -LiteralPath $env:ACL_PATH).Sddl",
            ])
            .env("ACL_PATH", dir.path().join(file))
            .output()
            .unwrap();
        let sddl = String::from_utf8(out.stdout).unwrap();
        let sddl = sddl.trim();
        let owner = &sddl[2..sddl.find("G:").unwrap()];
        let dacl = &sddl[sddl.find("D:").unwrap()..];
        assert!(dacl.starts_with("D:P"), "{file}: inherits: {sddl}");
        // Each entry is (type;flags;rights;;;SID): the owner, OWNER RIGHTS,
        // SYSTEM or administrators only (no Users, Everyone, ...).
        for ace in dacl.split('(').skip(1) {
            let sid = ace.trim_end_matches(')').rsplit(';').next().unwrap();
            assert!(
                ["OW", "SY", "BA", owner].contains(&sid),
                "{file}: {sid} in {sddl}"
            );
        }
    }
}

#[test]
fn a_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.hiccup");
    rusqlite::Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 99)
        .unwrap();
    assert!(matches!(Store::open(&path), Err(StoreError::TooNew(99))));
}

/// The acceptance benchmark: `cargo test --release -p hiccup-store -- --ignored`.
#[test]
#[ignore = "benchmark: run in release mode"]
fn ten_thousand_exchanges_p95_under_50ms() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(&dir.path().join("p.hiccup")).unwrap();
    let p95 = |mut times: Vec<Duration>| {
        times.sort();
        times[times.len() * 95 / 100]
    };
    let body = "x".repeat(2000);
    let mut inserts = Vec::new();
    for i in 0..10_000 {
        let request = format!("GET /item/{i} HTTP/1.1\r\nHost: h{}.test\r\n\r\n", i % 50);
        let response = format!(
            "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{body}",
            [200, 404, 500][i % 3],
            ["text/html", "application/json"][i % 2],
            body.len()
        );
        let e = exchange(
            &format!("h{}.test:443", i % 50),
            request.as_bytes(),
            Some(response.as_bytes()),
        );
        let t = Instant::now();
        store.insert(&e).unwrap();
        inserts.push(t.elapsed());
    }
    let filters = [
        Filter::default(),
        Filter {
            host: Some("h7.test".into()),
            ..Filter::default()
        },
        Filter {
            status: Some(500),
            mime: Some("application/".into()),
            ..Filter::default()
        },
        Filter {
            search: Some(b"/item/9999 ".to_vec()),
            ..Filter::default()
        },
    ];
    let mut queries = Vec::new();
    for _ in 0..25 {
        for f in &filters {
            // The first page, then the next one.
            let mut before = None;
            for _ in 0..2 {
                let t = Instant::now();
                let page = store.list(f, before, 100).unwrap();
                queries.push(t.elapsed());
                before = page.last().map(|s| s.id);
            }
        }
    }
    let (insert, query) = (p95(inserts), p95(queries));
    println!("p95: insert {insert:?}, query {query:?}");
    assert!(insert < Duration::from_millis(50), "insert p95 {insert:?}");
    assert!(query < Duration::from_millis(50), "query p95 {query:?}");
}
