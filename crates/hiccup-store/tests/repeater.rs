// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repeater tabs and their sends survive a reopen.

use std::time::{Duration, UNIX_EPOCH};

use hiccup_store::{RepeaterSend, Store, Tab};

fn sent(tab: i64, request: &[u8], response: &[u8], status: Option<u16>) -> RepeaterSend {
    RepeaterSend {
        id: 0,
        tab,
        started: UNIX_EPOCH + Duration::from_millis(1_790_000_000_000),
        duration: Duration::from_millis(31),
        host: "a.test".to_owned(),
        port: 8443,
        tls: true,
        status,
        error: None,
        details: r#"{"timings":{}}"#.to_owned(),
        request: request.to_vec(),
        response: response.to_vec(),
        response_size: 0,
    }
}

#[test]
fn tabs_and_their_sends_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.hiccup");
    let mut store = Store::open(&path).unwrap();
    let draft = Tab {
        id: 0,
        name: "login".to_owned(),
        host: "a.test".to_owned(),
        port: 8443,
        tls: true,
        request: b"POST /login HTTP/1.1\r\n\r\n\x00\xff".to_vec(),
        options: "{}".to_owned(),
    };
    let tab = store.create_tab(&draft).unwrap();
    let other = store
        .create_tab(&Tab {
            name: "other".to_owned(),
            ..draft.clone()
        })
        .unwrap();
    let ids = store
        .insert_sends(&[
            sent(tab.id, b"first", b"HTTP/1.1 302 Found\r\n\r\n", Some(302)),
            sent(tab.id, b"hop", b"HTTP/1.1 200 OK\r\n\r\nok", Some(200)),
        ])
        .unwrap();
    store
        .insert_sends(&[sent(other.id, b"x", b"", None)])
        .unwrap();
    let edited = Tab {
        name: "login v2".to_owned(),
        request: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        ..tab.clone()
    };
    assert!(store.update_tab(&edited).unwrap());
    drop(store);

    let mut store = Store::open(&path).unwrap();
    assert_eq!(store.tabs().unwrap(), [edited.clone(), other.clone()]);
    assert_eq!(store.tab(tab.id).unwrap(), Some(edited));

    // Newest first, without responses, paginated.
    let page = store.sends(tab.id, None, 10).unwrap();
    assert_eq!(
        page.iter().map(|s| s.id).collect::<Vec<_>>(),
        [ids[1], ids[0]]
    );
    assert!(page[0].response.is_empty());
    assert_eq!(page[0].response_size, 21);
    assert_eq!(store.sends(tab.id, Some(ids[1]), 10).unwrap().len(), 1);
    let one = store.send(ids[1]).unwrap().unwrap();
    assert_eq!(
        (one.request.as_slice(), one.response.as_slice()),
        (&b"hop"[..], &b"HTTP/1.1 200 OK\r\n\r\nok"[..])
    );
    assert_eq!((one.status, one.port, one.tls), (Some(200), 8443, true));
    assert_eq!(
        one.started,
        UNIX_EPOCH + Duration::from_millis(1_790_000_000_000)
    );
    assert_eq!(one.details, r#"{"timings":{}}"#);

    // Closing a tab deletes what was sent from it, and nothing else.
    assert!(store.delete_tab(tab.id).unwrap());
    assert!(!store.delete_tab(tab.id).unwrap());
    assert_eq!(store.send(ids[1]).unwrap(), None);
    assert_eq!(store.sends(other.id, None, 10).unwrap().len(), 1);
    assert!(!store.update_tab(&tab).unwrap(), "gone");
    // A send needs its tab.
    assert!(
        store
            .insert_sends(&[sent(tab.id, b"x", b"", None)])
            .is_err()
    );
}
