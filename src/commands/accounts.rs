//! `rhd accounts …` — the brokerage accounts inside one login.
//!
//! This is the *second* level of multi-account (see `config.rs`): one login
//! can hold an individual account, a joint account, an IRA, and so on.

use pk_cli_core::{CliError, Paged};
use serde::Serialize;
use serde_json::Value;

use crate::commands::{date_of, money_at, str_at, Ctx};

/// Collection endpoint. See docs/api.md §3.
pub const PATH: &str = "/accounts/";

/// Query for the collection.
///
/// `default_to_all_accounts=true` is what makes multi-account enumeration
/// actually work: without it the endpoint answers with the login's default
/// account only, so a household member's IRA or joint account silently never
/// appears. This is the single most important query parameter in the CLI.
///
/// It is not enough on its own. Managed ("Strategies") accounts and the
/// additional self-directed individual accounts a login can open stay hidden
/// unless asked for by name, with the two parameters the provider's own app
/// sends (docs/api.md §3.2). Without them a second individual account's
/// whole trading history is invisible to every read that enumerates
/// accounts.
pub fn all_accounts_query() -> Vec<(&'static str, String)> {
    vec![
        ("default_to_all_accounts", "true".to_string()),
        ("include_managed", "true".to_string()),
        ("include_multiple_individual", "true".to_string()),
    ]
}

/// `managed` (a Robinhood Strategies account) or `self_directed`, from the
/// wire's `management_type`.
pub fn management(v: &Value) -> Option<String> {
    str_at(v, "management_type")
}

/// Whether this row is the login's default account (`is_default: true`).
pub fn is_default(v: &Value) -> bool {
    v.get("is_default").and_then(Value::as_bool) == Some(true)
}

/// The account's `rhs_account_number` as a string. The wire carries it as
/// an **integer**; it equals `account_number` for most accounts but not for
/// a legacy default account whose `account_number` is alphanumeric
/// (docs/api.md §3.2). The ACATS listing (§3.13) names accounts by this
/// number, so a join must go through it, never through `account_number`.
pub fn rhs_number(v: &Value) -> Option<String> {
    match v.get("rhs_account_number")? {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Every account row in the login that carries an account number —
/// deactivated ones included, since a closed account can still hold this
/// year's trades. The enumeration `--all-accounts` reads fan out over.
pub fn addressable_rows(ctx: &Ctx, token: &str) -> Result<Vec<(String, Value)>, CliError> {
    let rows = ctx.rh.paginate(token, PATH, &all_accounts_query(), None)?;
    Ok(rows
        .into_iter()
        .filter_map(|r| str_at(&r, "account_number").map(|n| (n, r)))
        .collect())
}

/// The provider's account designation — live values are `individual`,
/// `ira_traditional`, `ira_roth`, `joint_tenancy_with_ros` (2026-08-21,
/// docs/api.md §3.2; note `ira_roth`, not the guessable `roth_ira`) —
/// falling back to the coarser `cash`/`margin` management style when the
/// richer field is absent.
///
/// The **one** reading of "what kind of account is this", shared by
/// `account-list/v1` (`kind`) and `net-worth/v1` (`accounts[].type`) so the
/// two DTOs agree — a consumer joining them must never see two different
/// designations for the same account.
pub fn designation(v: &Value) -> Option<String> {
    str_at(v, "brokerage_account_type").or_else(|| str_at(v, "type"))
}

/// Is this row an account that can currently hold value? Rows without an
/// `account_number` are unaddressable downstream; `deactivated` accounts are
/// closed. Pure, so the policy is unit-testable.
pub fn is_active_row(v: &Value) -> bool {
    str_at(v, "account_number").is_some()
        && v.get("deactivated").and_then(Value::as_bool) != Some(true)
}

/// Every **active** brokerage account row in the login, with the docs/api.md
/// §3.2 enumeration rules applied (`default_to_all_accounts=true`, or a
/// household member's IRA silently never appears).
///
/// Returned **keyed by account number**, so the addressability guarantee
/// travels with the data in the type — a caller can never reach a row whose
/// number is absent, and no downstream `expect` has to trust a filter in
/// this module by comment alone.
///
/// `accounts list` deliberately does *not* use this — a closed account
/// should stay visible in a listing — but a valuation rollup must not ask a
/// deactivated account for a portfolio.
pub fn active_rows(ctx: &Ctx, token: &str) -> Result<Vec<(String, Value)>, CliError> {
    let rows = ctx.rh.paginate(token, PATH, &all_accounts_query(), None)?;
    Ok(rows
        .into_iter()
        .filter(is_active_row)
        .filter_map(|r| str_at(&r, "account_number").map(|n| (n, r)))
        .collect())
}

/// One brokerage account (`account/v1`).
#[derive(Debug, Serialize)]
pub struct Account {
    /// The account number, which is what `-a/--account` matches.
    pub account_number: String,
    /// See [`designation`] — the same value `net-worth/v1` reports as its
    /// per-account `type`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The owner's own name for the account, set in the app. Omitted when
    /// unset (the wire carries `""`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// `managed` (Robinhood Strategies) or `self_directed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub management: Option<String>,
    /// Present (`true`) only on the login's default account — the one an
    /// unscoped order read answers for (docs/api.md §3.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buying_power: Option<pk_cli_core::Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cash: Option<pk_cli_core::Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Present only when the provider says the account is closed, so an open
    /// account's row stays uncluttered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

impl Account {
    pub fn from_json(v: &Value) -> Option<Self> {
        // No account number means nothing downstream can address it, so the
        // row is dropped rather than emitted half-formed.
        let account_number = str_at(v, "account_number")?;
        Some(Account {
            account_number,
            kind: designation(v),
            nickname: str_at(v, "nickname"),
            management: management(v),
            default: is_default(v).then_some(true),
            buying_power: money_at(v, "buying_power"),
            cash: money_at(v, "cash"),
            created: date_of(v, "created_at"),
            deactivated: match v.get("deactivated").and_then(Value::as_bool) {
                Some(true) => Some(true),
                _ => None,
            },
        })
    }
}

pub fn list(ctx: &Ctx) -> Result<(), CliError> {
    let token = ctx.access_token()?;
    let rows = ctx.rh.paginate(&token, PATH, &all_accounts_query(), None)?;
    let accounts: Vec<Account> = rows.iter().filter_map(Account::from_json).collect();
    Paged::new("account", accounts).emit(ctx.common.json);
    Ok(())
}

pub fn get(ctx: &Ctx, id: Option<&str>) -> Result<(), CliError> {
    // Fall back to the selected account so `accounts get` with a configured
    // default does the obvious thing.
    let wanted = match id {
        Some(i) => i.to_string(),
        None => ctx.require_account()?.to_string(),
    };

    let token = ctx.access_token()?;
    let rows = ctx.rh.paginate(&token, PATH, &all_accounts_query(), None)?;
    let found = rows
        .iter()
        .filter_map(Account::from_json)
        .find(|a| a.account_number == wanted)
        .ok_or_else(|| {
            CliError::NotFound(format!(
                "no brokerage account `{wanted}` in this login — run `rhd accounts list`"
            ))
        })?;

    crate::commands::emit_one("account", &found, ctx.common.json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "url": "https://api.robinhood.com/accounts/1010101010/",
            "account_number": "1010101010",
            "type": "margin",
            "buying_power": "1000.0000",
            "cash": "250.5000",
            "created_at": "2020-01-15T12:00:00.000000Z",
            "deactivated": false
        })
    }

    #[test]
    fn maps_the_fields_the_table_reads() {
        let a = Account::from_json(&sample()).unwrap();
        assert_eq!(a.account_number, "1010101010");
        assert_eq!(a.kind.as_deref(), Some("margin"));
        assert_eq!(a.created.as_deref(), Some("2020-01-15"));
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["buying_power"]["amount"], "1000.00");
        assert_eq!(v["cash"]["amount"], "250.50");
        // An open account omits `deactivated` rather than emitting false.
        assert!(v.get("deactivated").is_none());
        // Unset nickname, management and non-default are omitted too.
        assert!(v.get("nickname").is_none());
        assert!(v.get("management").is_none());
        assert!(v.get("default").is_none());
    }

    /// The enumeration asks for managed and additional individual accounts
    /// by name — without them a second individual account never appears
    /// (docs/api.md §3.2).
    #[test]
    fn the_query_asks_for_managed_and_multiple_individual_accounts() {
        let q = all_accounts_query();
        for key in [
            "default_to_all_accounts",
            "include_managed",
            "include_multiple_individual",
        ] {
            assert!(
                q.iter().any(|(k, v)| *k == key && v == "true"),
                "missing {key}=true"
            );
        }
    }

    #[test]
    fn nickname_management_default_and_rhs_number_are_read() {
        let mut v = sample();
        v["nickname"] = json!("Sample Nickname");
        v["management_type"] = json!("managed");
        v["is_default"] = json!(true);
        v["rhs_account_number"] = json!(100000001);
        let a = Account::from_json(&v).unwrap();
        assert_eq!(a.nickname.as_deref(), Some("Sample Nickname"));
        assert_eq!(a.management.as_deref(), Some("managed"));
        assert_eq!(a.default, Some(true));
        assert_eq!(rhs_number(&v).as_deref(), Some("100000001"));
        // The wire's empty nickname is "unset", not a name.
        v["nickname"] = json!("");
        assert!(Account::from_json(&v).unwrap().nickname.is_none());
    }

    /// `account-list/v1`'s `kind` and `net-worth/v1`'s per-account `type`
    /// come from the same reading, so a consumer joining the two DTOs never
    /// sees two different designations for one account.
    #[test]
    fn the_designation_prefers_the_richer_field_and_falls_back() {
        let mut v = sample();
        // The live wire spelling (docs/api.md §3.2) — not `roth_ira`.
        v["brokerage_account_type"] = json!("ira_roth");
        assert_eq!(
            Account::from_json(&v).unwrap().kind.as_deref(),
            Some("ira_roth")
        );
        assert_eq!(designation(&v).as_deref(), Some("ira_roth"));
        // Without the richer field, the cash/margin management style stands in.
        assert_eq!(designation(&sample()).as_deref(), Some("margin"));
        assert_eq!(designation(&json!({})), None);
    }

    /// The active-row policy the net-worth rollup depends on: unaddressable
    /// and closed accounts are out, everything else is in.
    #[test]
    fn active_rows_are_addressable_and_not_deactivated() {
        assert!(is_active_row(&sample()));
        let mut closed = sample();
        closed["deactivated"] = json!(true);
        assert!(!is_active_row(&closed));
        assert!(!is_active_row(&json!({"type": "margin"})));
        // `deactivated` absent (older shapes) still counts as active.
        let mut bare = sample();
        bare.as_object_mut().unwrap().remove("deactivated");
        assert!(is_active_row(&bare));
    }

    #[test]
    fn a_row_without_an_account_number_is_dropped() {
        // Nothing downstream could address it, and emitting a blank id would
        // make `-a` silently match nothing.
        assert!(Account::from_json(&json!({"type": "margin"})).is_none());
    }

    #[test]
    fn a_closed_account_says_so() {
        let mut v = sample();
        v["deactivated"] = json!(true);
        let a = Account::from_json(&v).unwrap();
        assert_eq!(a.deactivated, Some(true));
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new("account", vec![Account::from_json(&sample()).unwrap()]);
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "account-list/v1");
        assert_eq!(v["items"][0]["account_number"], "1010101010");
    }
}
