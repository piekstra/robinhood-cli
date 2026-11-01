//! `info` and `config` — the parts of the standard surface that need neither
//! the provider nor a credential.

use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs};

use crate::config::{Config, Profile, BIN, REPO};

/// `rhd info` — machine discovery (`cli-info/v1`).
pub fn info(json_mode: bool) -> Result<(), CliError> {
    let info = CliInfo::new(
        BIN,
        env!("CARGO_PKG_VERSION"),
        &format!("https://github.com/{REPO}"),
        AuthInfo {
            required: true,
            method: "browser-session".into(),
            login_hint: Some(login_hint()),
        },
        &[
            "profiles",
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
        ],
    )
    .with_profiles(&[pk_cli_documents::PROFILE]);
    let v = serde_json::to_value(&info).unwrap_or_default();
    if json_mode {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}

/// The browser sign-in first, then its fallback for a machine without
/// Chrome. The password login is left out: its device approval never reaches
/// the owner's phone (docs/api.md §2.8).
fn login_hint() -> String {
    format!(
        "{BIN} auth login --browser, or without Chrome: pbpaste | {BIN} auth login --session-stdin"
    )
}

/// The `config` subcommand, expressed without clap so this module does not
/// depend on the command tree.
pub enum ConfigOp<'a> {
    Path,
    Show,
    Set(&'a str, &'a str),
    Unset(&'a str),
}

pub fn config(
    common: &CommonArgs,
    store: &ConfigStore,
    mut cfg: Config,
    op: ConfigOp<'_>,
) -> Result<(), CliError> {
    match op {
        ConfigOp::Path => {
            println!("{}", store.path()?.display());
            Ok(())
        }
        ConfigOp::Show => {
            let v = serde_json::to_value(&cfg).unwrap_or_default();
            if common.json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
        ConfigOp::Set(key, value) => {
            match parse_key(key)? {
                Key::DefaultProfile => cfg.default_profile = Some(value.to_string()),
                Key::Username(p) => profile_mut(&mut cfg, p).username = Some(value.to_string()),
                Key::Account(p) => profile_mut(&mut cfg, p).account = Some(value.to_string()),
            }
            store.save(&cfg)
        }
        ConfigOp::Unset(key) => {
            match parse_key(key)? {
                Key::DefaultProfile => cfg.default_profile = None,
                Key::Username(p) => profile_mut(&mut cfg, p).username = None,
                Key::Account(p) => profile_mut(&mut cfg, p).account = None,
            }
            store.save(&cfg)
        }
    }
}

/// A settable config key. Profile-scoped keys are dotted so one flat key space
/// can address several logins: `spouse.account`.
#[derive(Debug)]
enum Key<'a> {
    DefaultProfile,
    Username(&'a str),
    Account(&'a str),
}

fn parse_key(key: &str) -> Result<Key<'_>, CliError> {
    if key == "default_profile" {
        return Ok(Key::DefaultProfile);
    }
    if let Some((profile, field)) = key.split_once('.') {
        if profile.is_empty() {
            return Err(CliError::Usage(
                "config key is missing a profile name before the `.`".into(),
            ));
        }
        return match field {
            "username" => Ok(Key::Username(profile)),
            "account" => Ok(Key::Account(profile)),
            other => Err(CliError::Usage(format!(
                "unknown config key `{profile}.{other}` (known: <profile>.username, \
                 <profile>.account)"
            ))),
        };
    }
    Err(CliError::Usage(format!(
        "unknown config key `{key}` (known: default_profile, <profile>.username, \
         <profile>.account)"
    )))
}

fn profile_mut<'a>(cfg: &'a mut Config, name: &str) -> &'a mut Profile {
    cfg.profiles.entry(name.to_string()).or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_keys_address_a_named_login() {
        assert!(matches!(
            parse_key("default_profile"),
            Ok(Key::DefaultProfile)
        ));
        assert!(matches!(
            parse_key("spouse.account"),
            Ok(Key::Account("spouse"))
        ));
        assert!(matches!(
            parse_key("primary.username"),
            Ok(Key::Username("primary"))
        ));
    }

    #[test]
    fn unknown_keys_are_usage_errors_that_name_the_alternatives() {
        let err = parse_key("nope").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("default_profile"));

        let err = parse_key("spouse.password").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        // Passwords are keychain-only; the config must never accept one.
        assert!(err.to_string().contains("unknown config key"));

        assert_eq!(parse_key(".username").unwrap_err().exit_code(), 2);
    }

    /// `config set` creates the profile if it doesn't exist yet, so the two
    /// ways of adding a login (`profiles add` and `config set`) agree.
    #[test]
    fn setting_a_profile_key_creates_the_profile() {
        let mut cfg = Config::default();
        profile_mut(&mut cfg, "spouse").account = Some("123".into());
        assert_eq!(
            cfg.profiles.get("spouse").unwrap().account.as_deref(),
            Some("123")
        );
    }

    #[test]
    fn info_declares_the_documents_profile_and_the_spec() {
        let info = CliInfo::new(
            BIN,
            "0.1.0",
            "https://github.com/piekstra/robinhood-cli",
            AuthInfo {
                required: true,
                method: "password".into(),
                login_hint: None,
            },
            &["accounts"],
        )
        .with_profiles(&[pk_cli_documents::PROFILE]);
        let v = serde_json::to_value(&info).unwrap();
        assert_eq!(v["schema"], "cli-info/v1");
        assert_eq!(v["spec"], "piekstra-cli/1");
        assert_eq!(v["name"], "rhd");
        assert_eq!(v["profiles"][0], "documents/v1");
    }
}
