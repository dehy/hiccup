// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup scope add|remove|list|test` against a running instance.

mod common;

use common::{Env, wait_exit};

fn stdout(env: &Env, args: &[&str]) -> String {
    let out = env.run(args);
    assert!(out.status.success(), "{args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn add_list_test_and_remove() {
    let env = Env::new();
    let (mut serve, _stderr) = env.spawn(&["serve"], "is running");

    assert!(stdout(&env, &["scope", "list"]).contains("everything is in scope"));
    let test = |url: &str| stdout(&env, &["scope", "test", url]);
    assert!(test("http://any.test/").contains("is in scope"));

    stdout(
        &env,
        &[
            "scope",
            "add",
            "--protocol",
            "https",
            "--host",
            "*.example.com",
        ],
    );
    let listed = stdout(&env, &["scope", "add", "--exclude", "--path", "^/logout"]);
    assert!(
        listed.contains("1  include https://*.example.com"),
        "{listed}"
    );
    assert!(
        listed.contains("2  exclude *://* path /^/logout/"),
        "{listed}"
    );

    assert!(test("https://app.example.com/a").contains("is in scope"));
    assert!(test("http://app.example.com/a").contains("out of scope"));
    assert!(test("https://app.example.com/logout").contains("out of scope"));
    assert!(test("https://other.test/").contains("out of scope"));

    // JSON: the rules as the control API returns them.
    let json = env.json(&["scope", "list"]);
    assert_eq!(json["rules"][0]["host"], "*.example.com");
    assert_eq!(json["rules"][1]["exclude"], true);
    assert_eq!(
        env.json(&["scope", "test", "https://app.example.com/"])["in_scope"],
        true
    );

    let left = stdout(&env, &["scope", "remove", "2"]);
    assert!(!left.contains("exclude"), "{left}");
    assert!(test("https://app.example.com/logout").contains("is in scope"));

    // Errors: a bad rule, a missing rule, not a URL.
    for (args, expected) in [
        (&["scope", "add", "--host", "a b"][..], "pattern"),
        (&["scope", "remove", "5"], "no scope rule"),
        (&["scope", "remove", "0"], "numbered from 1"),
        (
            &["scope", "test", "ftp://x/"],
            "not an http:// or https:// URL",
        ),
    ] {
        let out = env.run(args);
        assert!(!out.status.success(), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }

    // Intercept rules can use the scope.
    let status = stdout(&env, &["intercept", "on", "--in-scope"]);
    assert!(status.contains("Requests:  on (in scope)"), "{status}");

    assert!(env.run(&["instance", "stop"]).status.success());
    assert!(wait_exit(&mut serve).success());
}
