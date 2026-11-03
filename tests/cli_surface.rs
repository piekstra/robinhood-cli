//! Black-box tests over the built binary. Fully offline: nothing here touches
//! the network, and every test that could reach the keychain is either
//! config-isolated or opt-in.

use std::path::PathBuf;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use predicates::str::contains;

/// Tests that reach the OS keychain are opt-in.
///
/// Two reasons. On macOS, `cargo test` rebuilds an ad-hoc-signed binary each
/// run, which the OS treats as a new code identity — so a keychain read can
/// raise a permission dialog, and a developer who happens to have a real
/// session stored would get a different answer than a clean machine. On Linux
/// CI there is no D-Bus session at all, so the keyring backend errors
/// (exit 1) instead of reporting "no entry" (exit 3). Neither is a bug in the
/// CLI, and neither belongs in an offline gate.
///
/// Run them deliberately with `RHD_TEST_KEYCHAIN=1 cargo test`.
fn keychain_tests_enabled() -> bool {
    std::env::var("RHD_TEST_KEYCHAIN").as_deref() == Ok("1")
}

fn rhd() -> Command {
    let mut c = Command::cargo_bin("rhd").expect("binary builds");
    // No test touches the real server's token-refresh lock.
    let home = std::env::temp_dir().join(format!("rhd-test-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("temp dir");
    c.env("HOME", &home).env("USERPROFILE", &home);
    c
}

/// A throwaway config path, so a test never reads or writes the developer's
/// real `~/.config/rhd/config.json`.
fn scratch_config(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rhd-test-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join("config.json")
}

/// Run with an isolated config and no ambient profile/account selection, so
/// the developer's environment can't change a test's outcome.
fn isolated(tag: &str) -> Command {
    let mut c = rhd();
    c.arg("--config").arg(scratch_config(tag));
    c.env_remove("RHD_PROFILE").env_remove("RHD_ACCOUNT");
    c
}

const GROUPS: &[&str] = &[
    "auth",
    "profiles",
    "config",
    "accounts",
    "positions",
    "options",
    "transactions",
    "transfers",
    "dividends",
    "interest",
    "net-worth",
    "documents",
    "api",
    "self-update",
    "completions",
    "info",
    "mcp",
];

#[test]
fn top_level_help_lists_the_surface() {
    let out = rhd().arg("--help").assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for g in GROUPS {
        assert!(text.contains(g), "top-level help is missing `{g}`:\n{text}");
    }
    // The global flags the family spec requires.
    for flag in [
        "--json",
        "--verbose",
        "--quiet",
        "--no-color",
        "--profile",
        "--account",
    ] {
        assert!(text.contains(flag), "top-level help is missing `{flag}`");
    }
}

/// Rendering a subcommand's help forces clap's debug assertions to run over
/// that subtree, which is what catches conflicting short flags (e.g. a
/// subcommand `-a` colliding with the global `--account`).
#[test]
fn every_subcommand_help_renders() {
    for g in GROUPS {
        rhd().arg(g).arg("--help").assert().success();
    }
}

#[test]
fn nested_subcommand_help_renders() {
    let nested = [
        ["auth", "login"],
        ["auth", "status"],
        ["auth", "logout"],
        ["auth", "set-credential"],
        ["profiles", "list"],
        ["profiles", "add"],
        ["profiles", "remove"],
        ["profiles", "use"],
        ["config", "set"],
        ["accounts", "list"],
        ["accounts", "get"],
        ["positions", "list"],
        ["options", "positions"],
        ["transactions", "list"],
        ["transactions", "options"],
        ["transactions", "option-events"],
        ["transfers", "acats"],
        ["dividends", "list"],
        ["interest", "list"],
        ["documents", "list"],
        ["documents", "download"],
    ];
    for pair in nested {
        rhd()
            .args(pair)
            .arg("--help")
            .assert()
            .success()
            .stdout(contains("Usage"));
    }
}

#[test]
fn version_prints_the_crate_version() {
    rhd()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn info_emits_cli_info_dto() {
    let out = rhd().args(["info", "--json"]).assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("info emits JSON");
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["name"], "rhd");
    assert_eq!(v["auth"]["required"], true);
    assert_eq!(v["auth"]["method"], "browser-session");
    // The browser sign-in first, then its fallback, so a driver that reads
    // only `info` learns both.
    let hint = v["auth"]["login_hint"].as_str().expect("login_hint");
    assert!(hint.starts_with("rhd auth login --browser"), "{hint}");
    assert!(hint.contains("auth login --session-stdin"), "{hint}");
    // The documents domain profile is what an archiver keys off.
    assert_eq!(v["profiles"][0], "documents/v1");
    let caps = v["capabilities"].as_array().expect("capabilities array");
    for expected in [
        "accounts",
        "positions",
        "options",
        "transactions",
        "transfers",
        "net-worth",
        "documents",
        "api",
        "mcp",
    ] {
        assert!(
            caps.iter().any(|c| c == expected),
            "capabilities missing {expected}"
        );
    }
}

#[test]
fn unknown_command_is_a_usage_error() {
    rhd().arg("nope").assert().code(2);
}

// ------------------------------------------------------- auth login --browser

/// A Chrome that does not exist, so a regression that let `--browser` past
/// its flag checks fails on "no Chrome" instead of opening a window.
const NO_CHROME: &str = "/nonexistent/rhd-test-chrome";

/// `--browser` is the way in, so it leads the help, and its long help says
/// what opens, what is read from where, and how to point at another Chrome.
#[test]
fn auth_login_help_leads_with_browser() {
    let out = rhd().args(["auth", "login", "--help"]).assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for needle in [
        "--browser",
        "https://robinhood.com/login",
        "localStorage['web:auth_state']",
        "device_id",
        "the tab at once",
        "RHD_CHROME",
        "Without Chrome, use --session-stdin",
    ] {
        assert!(text.contains(needle), "help is missing {needle:?}:\n{text}");
    }
    let options = &text[text.find("Options:").expect("an Options section")..];
    let first = options.trim_start_matches("Options:").trim_start();
    assert!(
        first.starts_with("--browser"),
        "--browser must be the first option:\n{text}"
    );
    assert!(
        options.find("--browser").unwrap() < options.find("--session-stdin").unwrap(),
        "--browser must come before --session-stdin"
    );

    // The short help names it too.
    rhd()
        .args(["auth", "login", "-h"])
        .assert()
        .success()
        .stdout(contains("--browser"));
}

/// `--fresh-profile` picks the profile of a browser sign-in, so it means
/// nothing without `--browser`: exit 2 at parse time, before config, keychain,
/// Chrome or the network. Each of these reaches the network if it ever parses.
#[test]
fn fresh_profile_needs_the_browser_flag() {
    for extra in [
        &[][..],
        &["--session-stdin"],
        &["--stdin"],
        &["--from-env", "SOME_VAR"],
        &["--no-verify"],
        &["--code", "123456"],
        &["--resume"],
        &["--username", "user@example.com"],
        &["--channel", "email"],
    ] {
        let mut cmd = isolated("freshneedsbrowser");
        cmd.env("RHD_CHROME", NO_CHROME);
        piped(cmd)
            .args(["auth", "login", "--fresh-profile"])
            .args(extra)
            .write_stdin("Bearer SAMPLE-ACCESS-TOKEN-NOT-A-REAL-CREDENTIAL")
            .assert()
            .code(2);
    }
}

/// The help says the profile stays on disk, per login, and how to remove it.
#[test]
fn the_help_says_what_happens_to_the_kept_profile() {
    let out = rhd().args(["auth", "login", "--help"]).assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for needle in ["--fresh-profile", "keeps for", "rhd auth logout"] {
        assert!(text.contains(needle), "help is missing {needle:?}:\n{text}");
    }
    rhd()
        .args(["auth", "logout", "--help"])
        .assert()
        .success()
        .stdout(contains("kept browser profile"))
        .stdout(contains("first failure's code"))
        .stdout(contains("already cleared"));
    rhd()
        .args(["profiles", "remove", "--help"])
        .assert()
        .success()
        .stdout(contains("kept browser"))
        .stdout(contains("first failure's code"));
    // The command lists show the summary, on one line; the detail is above.
    for (group, command, summary) in [
        (
            "auth",
            "logout",
            "Clear the session and remove the kept browser profile",
        ),
        (
            "profiles",
            "remove",
            "Remove a login profile, its credentials and its kept browser profile",
        ),
    ] {
        let out = rhd().args([group, "--help"]).assert().success();
        let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
        let row = text
            .lines()
            .find(|l| l.trim_start().starts_with(command))
            .unwrap_or_else(|| panic!("no {command} row in:\n{text}"));
        assert!(row.trim_end().ends_with(summary), "{row}");
        assert!(!text.contains("first failure's code"), "{text}");
    }
}

/// A config that cannot be parsed says which login to log out when no flag does.
/// Logout does not guess: it stops here, before the keychain, and says how to go on.
#[test]
fn logout_with_a_broken_config_asks_which_login() {
    let config = scratch_config("brokenlogout");
    std::fs::write(&config, "not json").unwrap();
    rhd()
        .env_remove("RHD_PROFILE")
        .arg("--config")
        .arg(&config)
        .args(["auth", "logout"])
        .assert()
        .code(1)
        .stderr(contains("parsing"))
        .stderr(contains("--profile <NAME>"));
}

/// The Console snippet runs in the owner's own browser, so it must never change
/// what it reads.
#[test]
fn the_console_snippet_stays_read_only() {
    let out = rhd().args(["auth", "login", "--help"]).assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(text.contains("web:auth_state"), "{text}");
    assert!(!text.contains("removeItem"), "{text}");
}

/// A login whose name no kept browser profile can carry is refused before
/// Chrome starts, and stores nothing. With `--fresh-profile` it gets as far as
/// looking for Chrome, which is where this test stops (and no profile has been
/// touched by then).
#[test]
fn a_profile_name_no_browser_profile_can_carry_is_refused() {
    for name in ["has.dot", "has space"] {
        let config = scratch_config("browsername");
        let _ = std::fs::remove_file(&config);
        let mut login = rhd();
        login
            .arg("--config")
            .arg(&config)
            .env_remove("RHD_ACCOUNT")
            .env("RHD_PROFILE", name)
            .env("RHD_CHROME", NO_CHROME);
        login
            .args(["auth", "login", "--browser"])
            .assert()
            .code(2)
            .stderr(contains("1 to 64"))
            .stderr(contains("--fresh-profile"));
        let mut fresh = rhd();
        fresh
            .arg("--config")
            .arg(&config)
            .env_remove("RHD_ACCOUNT")
            .env("RHD_PROFILE", name)
            .env("RHD_CHROME", NO_CHROME);
        fresh
            .args(["auth", "login", "--browser", "--fresh-profile"])
            .assert()
            .code(1)
            .stderr(contains("RHD_CHROME"));
        assert!(!config.exists(), "{name}: wrote config for a refused login");
    }
}

#[test]
fn a_profile_name_too_long_for_a_browser_profile_cannot_be_added() {
    isolated("longname")
        .args(["profiles", "add", &"a".repeat(65)])
        .assert()
        .code(2);
}

/// `--browser` takes the session from the window: any other credential
/// source or password-login flag beside it is a usage error at parse time,
/// before config, keychain or network (and before Chrome).
#[test]
fn browser_refuses_every_other_source() {
    for extra in [
        &["--session-stdin"][..],
        &["--stdin"],
        &["--from-env", "SOME_VAR"],
        &["--no-verify"],
        &["--code", "123456"],
        &["--resume"],
        &["--username", "user@example.com"],
        &["--channel", "email"],
    ] {
        let config = scratch_config("browserconflict");
        let _ = std::fs::remove_file(&config);
        let mut cmd = rhd();
        cmd.arg("--config")
            .arg(&config)
            .env_remove("RHD_PROFILE")
            .env_remove("RHD_ACCOUNT")
            .env("RHD_CHROME", NO_CHROME);
        piped(cmd)
            .args(["auth", "login", "--browser"])
            .args(extra)
            .write_stdin("Bearer SAMPLE-ACCESS-TOKEN-NOT-A-REAL-CREDENTIAL")
            .assert()
            .code(2)
            .stderr(contains("cannot be used with"))
            .stderr(contains("--browser"));
        assert!(
            !config.exists(),
            "{extra:?}: wrote config for a refused login"
        );
    }
}

/// No Chrome is exit 1 naming the override variable and the DevTools
/// fallback, and nothing is stored.
#[test]
fn browser_without_chrome_points_at_the_fallback() {
    let config = scratch_config("browsernochrome");
    let _ = std::fs::remove_file(&config);
    let mut cmd = rhd();
    cmd.arg("--config")
        .arg(&config)
        .env_remove("RHD_PROFILE")
        .env_remove("RHD_ACCOUNT")
        .env("RHD_CHROME", NO_CHROME);
    let out = piped(cmd)
        .args(["--json", "auth", "login", "--browser"])
        .assert()
        .code(1)
        .stderr(contains("RHD_CHROME"))
        .stderr(contains("--session-stdin"));
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("error DTO on stdout");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("RHD_CHROME"));
    assert!(!config.exists(), "wrote config without a session");
}

// ------------------------------------------------- auth login --session-stdin

/// The same command, able to take piped stdin.
fn piped(cmd: Command) -> assert_cmd::Command {
    assert_cmd::Command::from_std(cmd)
}

/// The help is the owner's walkthrough: it has to name the DevTools panel,
/// key and header for each shape, and the pipe.
#[test]
fn session_stdin_help_walks_through_both_captures() {
    let out = rhd().args(["auth", "login", "--help"]).assert().success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for needle in [
        "--session-stdin",
        "Console",
        "localStorage['web:auth_state']",
        "device_id",
        "Application > Local Storage",
        "Network",
        "authorization",
        "Bearer",
        "pbpaste | rhd auth login --session-stdin",
        "do not click Log out",
    ] {
        assert!(text.contains(needle), "help is missing {needle:?}:\n{text}");
    }
}

/// A browser import has nothing to do with the password, the challenge
/// resume or the code channel; combining them is a usage error, not a
/// silently ignored flag.
#[test]
fn session_stdin_refuses_the_password_flags() {
    for extra in [
        &["--code", "123456"][..],
        &["--resume"],
        &["--stdin"],
        &["--from-env", "SOME_VAR"],
        &["--username", "user@example.com"],
        &["--channel", "email"],
        &["--no-verify"],
    ] {
        piped(isolated("sessconflict"))
            .args(["auth", "login", "--session-stdin"])
            .args(extra)
            .write_stdin("Bearer SAMPLE-ACCESS-TOKEN-NOT-A-REAL-CREDENTIAL")
            .assert()
            .code(2)
            .stderr(contains("cannot be used with"));
    }
}

/// Bad input fails as usage before the keychain or the network — so it
/// also leaves no config behind — and the error never repeats the input.
#[test]
fn session_stdin_rejects_input_it_cannot_read() {
    let secret = "SAMPLE-SECRET-THAT-MUST-NOT-ECHO";
    for (tag, input) in [
        ("sessempty", String::new()),
        ("sessgarbage", format!("{secret} {secret}")),
        ("sessnotoken", format!("{{\"refresh_token\":\"{secret}\"}}")),
        ("sessbroken", format!("{{\"access_token\":\"{secret}\"")),
        (
            "sessdevice",
            format!("{{\"access_token\":\"{secret}\",\"device_token\":\"nope\"}}"),
        ),
    ] {
        let config = scratch_config(tag);
        let mut cmd = rhd();
        cmd.arg("--config")
            .arg(&config)
            .env_remove("RHD_PROFILE")
            .env_remove("RHD_ACCOUNT");
        let out = piped(cmd)
            .args(["auth", "login", "--session-stdin"])
            .write_stdin(input)
            .assert()
            .code(2);
        let output = out.get_output();
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!all.contains(secret), "{tag}: echoed the input: {all}");
        assert!(!config.exists(), "{tag}: wrote config for a refused import");
    }
}

/// Bad input fails at once even while another process holds the lock the write
/// would need: waiting would exit 5 after 75 s and never mention the input.
#[test]
fn session_stdin_rejects_bad_input_without_waiting_on_a_busy_lock() {
    let home = tempfile::tempdir().unwrap();
    pk_cli_auth::refresh_lock::RefreshLock::at(home.path().join(".config/rhd/token-refresh.lock"))
        .hold(|| {
            let mut cmd = rhd();
            cmd.arg("--config")
                .arg(scratch_config("sessbusy"))
                .env("HOME", home.path())
                .env("USERPROFILE", home.path())
                .env_remove("RHD_PROFILE")
                .env_remove("RHD_ACCOUNT");
            piped(cmd)
                .args(["auth", "login", "--session-stdin"])
                .write_stdin("{not json")
                .assert()
                .code(2);
            Ok(())
        })
        .unwrap();
}

#[test]
fn session_stdin_errors_use_the_family_error_dto() {
    let out = piped(isolated("sessjson"))
        .args(["--json", "auth", "login", "--session-stdin"])
        .write_stdin("not a session")
        .assert()
        .code(2);
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("error DTO on stdout");
    assert_eq!(v["error"]["code"], "usage");
}

/// A token that says it has expired is refused locally (exit 3) — the
/// proving read could only 401, and the remedy is reloading the page.
#[test]
fn an_expired_capture_never_reaches_the_network() {
    // An unsigned JWT whose payload is {"exp":1000000000} (2001), assembled
    // from its segments so no line reads as a credential to secret scanners.
    let claims = "eyJleHAiOjEwMDAwMDAwMDB9";
    let jwt = ["header", claims, "signature"].join(".");
    piped(isolated("sessexpired"))
        .args(["auth", "login", "--session-stdin"])
        .write_stdin(format!("Bearer {jwt}"))
        .assert()
        .code(3)
        .stderr(contains("expired at 2001-09-09"))
        .stderr(contains("reload robinhood.com"))
        .stderr(contains("nothing was stored"));
}

/// Dates are validated before any config load, so this is a usage error even
/// on a machine that has never run `rhd profiles add`.
#[test]
fn bad_date_is_a_usage_error() {
    isolated("baddate")
        .args(["transactions", "list", "--since", "06/30/2026"])
        .assert()
        .code(2);
}

/// The options feed validates its dates the same way — before config,
/// keychain, or network.
#[test]
fn options_bad_date_is_a_usage_error() {
    isolated("optbaddate")
        .args(["transactions", "options", "--since", "06/30/2026"])
        .assert()
        .code(2);
}

/// The option-events feed validates its dates the same way — before
/// config, keychain, or network.
#[test]
fn option_events_bad_date_is_a_usage_error() {
    isolated("evtbaddate")
        .args(["transactions", "option-events", "--since", "06/30/2026"])
        .assert()
        .code(2);
    isolated("evtinverted")
        .args([
            "transactions",
            "option-events",
            "--since",
            "2026-12-31",
            "--until",
            "2026-01-01",
        ])
        .assert()
        .code(2);
}

/// Every read that can fan out advertises `--all-accounts`.
#[test]
fn the_all_accounts_flag_is_on_every_fan_out_read() {
    for args in [
        ["positions", "list"],
        ["options", "positions"],
        ["transactions", "list"],
        ["transactions", "options"],
        ["transactions", "option-events"],
    ] {
        rhd()
            .args(args)
            .arg("--help")
            .assert()
            .success()
            .stdout(contains("--all-accounts"));
    }
}

/// `--all-accounts` with an explicit account is a contradiction, refused as
/// a usage error before any config, keychain or network is touched — the
/// isolated config here has no profile, which would otherwise be the error.
#[test]
fn all_accounts_conflicts_with_an_explicit_account() {
    for args in [
        vec!["positions", "list", "--all-accounts"],
        vec!["options", "positions", "--all-accounts"],
        vec!["transactions", "list", "--all-accounts"],
        vec!["transactions", "options", "--all-accounts"],
        vec!["transactions", "option-events", "--all-accounts"],
    ] {
        isolated("allacct")
            .args(&args)
            .args(["-a", "SAMPLE01"])
            .assert()
            .code(2)
            .stderr(contains("--all-accounts"));
        isolated("allacctenv")
            .args(&args)
            .env("RHD_ACCOUNT", "SAMPLE01")
            .assert()
            .code(2);
    }
}

/// The ACATS listing validates its range before config, keychain, or
/// network, like every dated read.
#[test]
fn transfers_acats_validates_its_range_first() {
    rhd()
        .args(["transfers", "acats", "--help"])
        .assert()
        .success()
        .stdout(contains("--since"));
    isolated("acatsbaddate")
        .args(["transfers", "acats", "--since", "06/30/2026"])
        .assert()
        .code(2);
}

/// Both order feeds advertise the per-fill detail flag.
#[test]
fn the_executions_flag_is_on_both_order_feeds() {
    for sub in ["list", "options"] {
        rhd()
            .args(["transactions", sub, "--help"])
            .assert()
            .success()
            .stdout(contains("--executions"));
    }
}

#[test]
fn inverted_range_is_a_usage_error() {
    isolated("inverted")
        .args([
            "transactions",
            "list",
            "--since",
            "2026-12-31",
            "--until",
            "2026-01-01",
        ])
        .assert()
        .code(2);
}

/// Read-only is a safety property, so a write verb must be refused before the
/// keychain or the network is touched.
#[test]
fn api_refuses_anything_but_get() {
    for method in ["POST", "PUT", "DELETE", "patch"] {
        isolated("apiverb")
            .args(["api", method, "/accounts/"])
            .assert()
            .code(2)
            .stderr(contains("read-only"));
    }
}

#[test]
fn api_accepts_get_far_enough_to_need_credentials() {
    if !keychain_tests_enabled() {
        return;
    }
    // No session configured, so this must fail as auth (3) — proving the verb
    // check passed and the failure is about credentials, not usage.
    isolated("apiget")
        .args(["-p", "rhdtestabsent", "api", "GET", "/accounts/"])
        .assert()
        .code(3);
}

#[test]
fn documents_download_requires_a_target() {
    isolated("dltarget")
        .args(["documents", "download"])
        .assert()
        .code(2);
    isolated("dlboth")
        .args(["documents", "download", "abc", "--all"])
        .assert()
        .code(2);
}

#[test]
fn json_errors_use_the_family_error_dto() {
    let out = isolated("jsonerr")
        .args(["transactions", "list", "--since", "nope", "--json"])
        .assert()
        .code(2);
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("error DTO on stdout");
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["message"].is_string());
}

/// With no credentials stored, a read must fail as auth (3) with a message
/// pointing at login — not panic, and not claim an empty portfolio. Includes
/// `net-worth`, which must never report $0 for "not logged in".
#[test]
fn a_read_without_credentials_is_an_auth_error() {
    if !keychain_tests_enabled() {
        return;
    }
    for (tag, args) in [
        ("noauth", &["positions", "list"][..]),
        ("noauthnw", &["net-worth"][..]),
        ("noauthopt", &["options", "positions"][..]),
        ("noauthevt", &["transactions", "option-events"][..]),
    ] {
        isolated(tag)
            .args(["-p", "rhdtestabsent"])
            .args(args)
            .assert()
            .code(3)
            .stderr(contains("auth login"));
    }
}

#[test]
fn profiles_list_is_empty_on_a_fresh_install() {
    let out = isolated("freshprofiles")
        .args(["profiles", "list", "--json"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("profiles list emits JSON");
    assert_eq!(v["schema"], "login-profile-list/v1");
    assert_eq!(v["items"].as_array().map(Vec::len), Some(0));
}

/// The multi-login safety rail, end to end through the binary: two profiles
/// and no default must refuse to guess.
#[test]
fn two_profiles_without_a_default_refuse_to_guess() {
    let cfg = scratch_config("ambiguous");
    std::fs::write(
        &cfg,
        r#"{"profiles":{"alice":{"username":"a@example.com"},"bob":{"username":"b@example.com"}}}"#,
    )
    .expect("write config");

    let mut c = rhd();
    c.env_remove("RHD_PROFILE").env_remove("RHD_ACCOUNT");
    c.arg("--config")
        .arg(&cfg)
        .args(["positions", "list"])
        .assert()
        .code(2)
        .stderr(contains("alice"))
        .stderr(contains("bob"));
}

/// ...but naming one gets past profile resolution, failing on credentials.
#[test]
fn naming_a_profile_resolves_the_ambiguity() {
    if !keychain_tests_enabled() {
        return;
    }
    let cfg = scratch_config("named");
    std::fs::write(
        &cfg,
        r#"{"profiles":{"alice":{"username":"a@example.com"},"bob":{"username":"b@example.com"}}}"#,
    )
    .expect("write config");

    let mut c = rhd();
    c.env_remove("RHD_PROFILE").env_remove("RHD_ACCOUNT");
    c.arg("--config")
        .arg(&cfg)
        .args(["-p", "alice", "positions", "list"])
        .assert()
        .code(3);
}

#[test]
fn an_unknown_profile_is_not_found() {
    let cfg = scratch_config("unknown");
    std::fs::write(&cfg, r#"{"profiles":{"alice":{}}}"#).expect("write config");

    let mut c = rhd();
    c.env_remove("RHD_PROFILE").env_remove("RHD_ACCOUNT");
    c.arg("--config")
        .arg(&cfg)
        .args(["-p", "carol", "positions", "list"])
        .assert()
        .code(4);
}

/// Regression: the global `-a/--account` must reach `auth status`, not just
/// the read commands.
///
/// This was wired wrong once — `status` was passed `None` instead of the flag,
/// so only the `RHD_ACCOUNT` env fallback appeared to work and `auth status`
/// reported a different account than the very next command would act on. Unit
/// tests could not see it: the resolver was correct, the *call site* was not.
#[test]
fn the_account_flag_reaches_auth_status() {
    if !keychain_tests_enabled() {
        return;
    }
    let cfg = scratch_config("acctflag");
    std::fs::write(
        &cfg,
        r#"{"profiles":{"rhdtestabsent":{"account":"FROMCONFIG"}}}"#,
    )
    .expect("write config");

    let mut c = rhd();
    c.env_remove("RHD_PROFILE").env_remove("RHD_ACCOUNT");
    let out = c
        .arg("--config")
        .arg(&cfg)
        .args([
            "-p",
            "rhdtestabsent",
            "-a",
            "FROMFLAG",
            "auth",
            "status",
            "--json",
        ])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("auth status emits JSON");
    assert_eq!(
        v["account"], "FROMFLAG",
        "the -a flag must win over the profile's configured default"
    );
}

#[test]
fn config_roundtrips_a_profile_key() {
    let cfg = scratch_config("configset");
    let _ = std::fs::remove_file(&cfg);

    rhd()
        .arg("--config")
        .arg(&cfg)
        .args(["config", "set", "spouse.account", "1010101010"])
        .assert()
        .success();

    let out = rhd()
        .arg("--config")
        .arg(&cfg)
        .args(["config", "show", "--json"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("config show emits JSON");
    assert_eq!(v["profiles"]["spouse"]["account"], "1010101010");
}

#[test]
fn config_rejects_a_password_key() {
    // Passwords are keychain-only; the config file must never accept one.
    isolated("configpw")
        .args(["config", "set", "spouse.password", "hunter2"])
        .assert()
        .code(2);
}

/// Removing a profile destroys stored credentials, so it needs confirmation
/// and must exit 6 when there is nobody to ask.
#[test]
fn removing_a_profile_non_interactively_needs_force() {
    let cfg = scratch_config("rmprofile");
    std::fs::write(&cfg, r#"{"profiles":{"alice":{}}}"#).expect("write config");

    rhd()
        .arg("--config")
        .arg(&cfg)
        .args(["profiles", "remove", "alice"])
        .assert()
        .code(6);
}

#[test]
fn completions_generate_for_each_shell() {
    for shell in ["bash", "zsh", "fish"] {
        rhd()
            .args(["completions", shell])
            .assert()
            .success()
            .stdout(predicates::str::is_empty().not());
    }
}

/// no-color.org: any non-empty `NO_COLOR` turns color off. cli-common before
/// v0.15.1 parsed it as a clap bool, so `NO_COLOR=1` failed every command with
/// a usage error.
#[test]
fn no_color_in_the_environment_never_fails_a_command() {
    for v in ["1", "true", "0", ""] {
        isolated("no-color")
            .env("NO_COLOR", v)
            .args(["completions", "bash"])
            .assert()
            .success();
    }
}
