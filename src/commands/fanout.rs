//! `--all-accounts` — one read per brokerage account in the login, every row
//! verified against the account it was requested for and tagged with it.
//!
//! An unscoped order read answers for the login's **default** account only
//! (docs/api.md §3.4), so a second individual account's trades never appear
//! in it. Reading each account with its own scoping parameter is the only
//! complete read; verifying that every returned row names that account is
//! what makes it truthful — the same rail `net-worth` runs (§3.8), because a
//! parameter the server silently ignores would otherwise report one
//! account's rows under another's number.

use pk_cli_core::CliError;
use serde_json::Value;

use crate::commands::{accounts, str_at, Ctx};

/// Private keys the fan-out stamps on a raw row so the DTO mapping can read
/// the tags back. Double-underscored so no wire key can collide with them.
const KIND_KEY: &str = "__rhd_account_kind";
const DEFAULT_KEY: &str = "__rhd_account_default";

/// One account to read: its number, its designation and whether it is the
/// login's default account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub number: String,
    pub kind: Option<String>,
    pub default: bool,
}

impl Scope {
    pub fn of(number: &str, row: &Value) -> Self {
        Scope {
            number: number.to_string(),
            kind: accounts::designation(row),
            default: accounts::is_default(row),
        }
    }
}

/// The accounts a fan-out reads. `active_only` drops deactivated accounts —
/// right for holdings (a closed account holds nothing), wrong for history (a
/// closed account can hold this year's trades), so history reads pass
/// `false`.
pub fn scopes(rows: &[(String, Value)], active_only: bool) -> Vec<Scope> {
    rows.iter()
        .filter(|(_, r)| !active_only || accounts::is_active_row(r))
        .map(|(n, r)| Scope::of(n, r))
        .collect()
}

/// The account number in `https://api.robinhood.com/accounts/<n>/`.
pub fn account_from_url(url: &str) -> Option<String> {
    let mut parts = url.trim_end_matches('/').rsplit('/');
    let last = parts.next()?;
    (parts.next() == Some("accounts") && !last.is_empty()).then(|| last.to_string())
}

/// The account a row names: its direct `account_number`, else the number
/// in its `account` URL — equity order rows carry only the URL live
/// (docs/api.md §3.4).
pub fn row_account(v: &Value) -> Option<String> {
    str_at(v, "account_number").or_else(|| str_at(v, "account").and_then(|u| account_from_url(&u)))
}

/// The designation the fan-out tagged a row with.
pub fn kind_of(v: &Value) -> Option<String> {
    str_at(v, KIND_KEY)
}

/// `Some(true)` on a row the fan-out read from the default account; `None`
/// otherwise (the DTO omits the key rather than emitting `false`).
pub fn default_of(v: &Value) -> Option<bool> {
    (v.get(DEFAULT_KEY).and_then(Value::as_bool) == Some(true)).then_some(true)
}

/// Verify every row of one account's read names that account, then tag it.
///
/// A row naming another account means the scoping parameter was ignored;
/// a row naming none cannot be attributed. Either refuses the whole read
/// (exit 5): a complete-looking listing with misattributed rows is worse
/// than no listing. Pure, so the rail is pinned offline.
pub fn verify_and_tag(rows: Vec<Value>, scope: &Scope, what: &str) -> Result<Vec<Value>, CliError> {
    rows.into_iter()
        .map(|mut r| {
            let owner = row_account(&r).ok_or_else(|| {
                CliError::Upstream(format!(
                    "a {what} row in account {}'s read names no account — cannot attribute it; \
                     refusing the read (docs/api.md §3.14)",
                    scope.number
                ))
            })?;
            if owner != scope.number {
                return Err(CliError::Upstream(format!(
                    "the {what} read for account {} returned a row belonging to account {owner} \
                     — the account filter was ignored; refusing to misattribute it \
                     (docs/api.md §3.14)",
                    scope.number
                )));
            }
            if let Some(obj) = r.as_object_mut() {
                obj.insert("account_number".into(), Value::String(scope.number.clone()));
                if let Some(k) = &scope.kind {
                    obj.insert(KIND_KEY.into(), Value::String(k.clone()));
                }
                if scope.default {
                    obj.insert(DEFAULT_KEY.into(), Value::Bool(true));
                }
            }
            Ok(r)
        })
        .collect()
}

/// Read every account with `fetch` (which issues that account's scoped
/// read), verifying and tagging each account's rows. Rows come back in
/// account order; callers sort the merged set themselves. One pass, no
/// retries: a failed account read fails the whole command.
pub fn read_all(
    ctx: &Ctx,
    token: &str,
    active_only: bool,
    what: &str,
    fetch: impl FnMut(&Scope) -> Result<Vec<Value>, CliError>,
) -> Result<Vec<Value>, CliError> {
    let listed = accounts::addressable_rows(ctx, token)?;
    read_listed(&listed, active_only, what, fetch)
}

/// [`read_all`] over an accounts listing already in hand. Pure apart from
/// `fetch`, so the whole rail is pinned offline.
///
/// An empty listing is a shape surprise (every login has an account). A
/// listing whose accounts are all closed, under a holdings read, is simply
/// nothing to read — an empty result, not an error.
pub fn read_listed(
    listed: &[(String, Value)],
    active_only: bool,
    what: &str,
    mut fetch: impl FnMut(&Scope) -> Result<Vec<Value>, CliError>,
) -> Result<Vec<Value>, CliError> {
    if listed.is_empty() {
        return Err(CliError::Upstream(
            "Robinhood returned no brokerage accounts to read — if this login really has none \
             that is new information; otherwise the accounts shape has changed (docs/api.md §3.2)"
                .into(),
        ));
    }
    let mut out = Vec::new();
    for scope in &scopes(listed, active_only) {
        out.extend(verify_and_tag(fetch(scope)?, scope, what)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope(n: &str) -> Scope {
        Scope {
            number: n.into(),
            kind: Some("individual".into()),
            default: false,
        }
    }

    #[test]
    fn the_account_comes_from_the_field_or_the_url() {
        assert_eq!(
            account_from_url("https://api.robinhood.com/accounts/SAMPLE01/").as_deref(),
            Some("SAMPLE01")
        );
        assert_eq!(
            account_from_url("https://api.robinhood.com/instruments/x/"),
            None
        );
        assert_eq!(account_from_url(""), None);
        let url_only = json!({"account": "https://api.robinhood.com/accounts/SAMPLE02/"});
        assert_eq!(row_account(&url_only).as_deref(), Some("SAMPLE02"));
        // The direct field wins where both exist.
        let both = json!({"account_number": "SAMPLE01",
                          "account": "https://api.robinhood.com/accounts/SAMPLE02/"});
        assert_eq!(row_account(&both).as_deref(), Some("SAMPLE01"));
    }

    #[test]
    fn verified_rows_are_tagged_with_their_account() {
        let rows =
            vec![json!({"id": "1", "account": "https://api.robinhood.com/accounts/SAMPLE01/"})];
        let mut s = scope("SAMPLE01");
        s.default = true;
        let tagged = verify_and_tag(rows, &s, "order").unwrap();
        assert_eq!(tagged[0]["account_number"], "SAMPLE01");
        assert_eq!(kind_of(&tagged[0]).as_deref(), Some("individual"));
        assert_eq!(default_of(&tagged[0]), Some(true));

        let other = verify_and_tag(
            vec![json!({"account_number": "SAMPLE01"})],
            &scope("SAMPLE01"),
            "order",
        )
        .unwrap();
        assert_eq!(default_of(&other[0]), None);
    }

    /// The rail: a row for another account means the filter was ignored,
    /// and the whole read is refused rather than misattributed.
    #[test]
    fn a_row_for_another_account_refuses_the_read() {
        let rows = vec![
            json!({"account_number": "SAMPLE01"}),
            json!({"account_number": "SAMPLE02"}),
        ];
        let err = verify_and_tag(rows, &scope("SAMPLE01"), "order").unwrap_err();
        assert!(matches!(err, CliError::Upstream(_)));
        assert!(err.to_string().contains("ignored"));
    }

    #[test]
    fn a_row_naming_no_account_refuses_the_read() {
        let err =
            verify_and_tag(vec![json!({"id": "1"})], &scope("SAMPLE01"), "order").unwrap_err();
        assert!(matches!(err, CliError::Upstream(_)));
    }

    #[test]
    fn history_reads_keep_closed_accounts_and_holdings_reads_drop_them() {
        let rows = vec![
            (
                "SAMPLE01".to_string(),
                json!({"account_number": "SAMPLE01", "is_default": true,
                "brokerage_account_type": "individual"}),
            ),
            (
                "SAMPLE02".to_string(),
                json!({"account_number": "SAMPLE02", "deactivated": true,
                "brokerage_account_type": "ira_roth"}),
            ),
        ];
        let all = scopes(&rows, false);
        assert_eq!(all.len(), 2);
        assert!(all[0].default);
        assert_eq!(all[1].kind.as_deref(), Some("ira_roth"));
        assert_eq!(scopes(&rows, true).len(), 1);
    }

    fn listed() -> Vec<(String, Value)> {
        vec![
            (
                "SAMPLE01".to_string(),
                json!({"account_number": "SAMPLE01", "is_default": true,
                "brokerage_account_type": "individual"}),
            ),
            (
                "SAMPLE02".to_string(),
                json!({"account_number": "SAMPLE02",
                "brokerage_account_type": "ira_roth"}),
            ),
        ]
    }

    /// The whole fan-out end to end: one scoped read per account, merged and
    /// tagged — including an order row that names its account by URL only.
    #[test]
    fn every_account_is_read_and_tagged() {
        let rows = read_listed(&listed(), false, "order", |s| {
            Ok(vec![json!({"id": s.number.clone(),
                "account": format!("https://api.robinhood.com/accounts/{}/", s.number)})])
        })
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["account_number"], "SAMPLE01");
        assert_eq!(default_of(&rows[0]), Some(true));
        assert_eq!(kind_of(&rows[1]).as_deref(), Some("ira_roth"));
        assert_eq!(default_of(&rows[1]), None);
    }

    /// A read the server answered for the wrong account fails the whole
    /// fan-out with an upstream error — exit 5 — and so does a row that
    /// names no account at all.
    #[test]
    fn a_misattributed_or_unattributable_row_fails_the_fan_out_with_exit_5() {
        for bad in [json!({"account_number": "SAMPLE01"}), json!({"id": "x"})] {
            let err = read_listed(&listed(), false, "order", |s| {
                Ok(if s.number == "SAMPLE02" {
                    vec![bad.clone()]
                } else {
                    vec![]
                })
            })
            .unwrap_err();
            assert!(matches!(err, CliError::Upstream(_)));
            assert_eq!(err.exit_code(), 5);
        }
    }

    #[test]
    fn all_closed_accounts_read_as_nothing_but_an_empty_listing_is_a_surprise() {
        let closed = vec![(
            "SAMPLE01".to_string(),
            json!({"account_number": "SAMPLE01", "deactivated": true}),
        )];
        let rows = read_listed(&closed, true, "position", |_| panic!("no read expected")).unwrap();
        assert!(rows.is_empty());
        assert!(read_listed(&[], true, "position", |_| Ok(vec![])).is_err());
    }
}
