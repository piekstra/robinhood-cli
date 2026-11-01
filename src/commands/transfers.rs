//! `rhd transfers acats` — account transfers between brokerages (ACATS).
//!
//! Shares that arrive by ACATS arrive **without an order**, so no order feed
//! records them; a realized-gains consumer that walks orders finds a sale
//! with no buy. This listing is where the provider records them — with three
//! traps (docs/api.md §3.13):
//!
//! - it lives on the `bonfire` host, not `api.robinhood.com`, and only
//!   answers both directions when asked (`both_directions=true`);
//! - a row names its account by `rhs_account_number`, which is **not**
//!   always the `account_number` every other endpoint uses, so the join goes
//!   through the accounts listing;
//! - it carries **no cost basis** and no per-asset value: quantities only.
//!   The basis travels between the brokers' books, not through this API.
//!
//! And one gap: a transfer into one of a login's additional individual
//! accounts was absent from every known listing live, so a consumer must
//! still infer a transfer-in from the receiving account's positions and
//! sales when the listing is silent.

use std::collections::HashMap;

use pk_cli_core::{output, CliError, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use crate::commands::{accounts, date_of, date_within, str_at, trim_quantity, Ctx};
use crate::config::{API_BASE, BONFIRE_BASE};

pub const ACATS_PATH: &str = "/acats/";

/// One asset leg of a transfer.
#[derive(Debug, Serialize, PartialEq)]
pub struct AcatsAsset {
    /// `equity` | `cash` (other wire values pass through).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_type: Option<String>,
    /// Resolved from the instrument; omitted when it did not resolve —
    /// a wrong ticker is worse than a missing one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument_id: Option<String>,
    /// Shares for an equity leg, the amount for a cash leg — unsigned;
    /// `direction` carries the sense.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    /// `long` | `short` — on a cash leg, `short` is a debit (a fee or a
    /// debit balance carried across), `long` a credit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// ISO currency of a cash leg.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

impl AcatsAsset {
    fn from_json(v: &Value, symbols: &HashMap<String, String>) -> Self {
        let instrument_id = instrument_id_of(v);
        AcatsAsset {
            asset_type: str_at(v, "asset_type"),
            symbol: instrument_id
                .as_deref()
                .and_then(|id| symbols.get(&instrument_url(id)))
                .cloned(),
            instrument_id,
            quantity: str_at(v, "quantity").map(|q| trim_quantity(&q)),
            direction: str_at(v, "direction"),
            currency: str_at(v, "iso_currency_code"),
        }
    }
}

/// One ACATS transfer (`acats-transfer/v1`).
#[derive(Debug, Serialize)]
pub struct AcatsTransfer {
    pub id: String,
    /// The transfer's date: settlement when settled, else when requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// `incoming` | `outgoing`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// The wire's `phase`: `settled`, `rejected`, or an in-flight phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// `full` | `partial` | `residual` (a later sweep of leftover cash).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_date: Option<String>,
    /// Only while the transfer has not settled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_settlement_date: Option<String>,
    /// The Robinhood account, joined from `rhs_account_number` through the
    /// accounts listing (docs/api.md §3.13).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_kind: Option<String>,
    /// `true` when the account is the login's default (the same mark the
    /// `--all-accounts` reads carry); omitted otherwise. A consumer keeping
    /// the default account's rows in one book needs it here too: the
    /// listing names the account, never whether it is the default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_default: Option<bool>,
    /// The wire's account reference, kept only when it matched no account
    /// in the login — so the row stays attributable by hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rhs_account_number: Option<String>,
    /// The other brokerage's name (null on the wire for a residual sweep).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contra_broker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contra_dtcc_number: Option<String>,
    /// Only on a rejected transfer: the wire fills `reject_reason` with a
    /// support link even on settled rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    pub assets: Vec<AcatsAsset>,
}

/// A row's account reference: `rhs_account_number`, an integer on the wire.
fn rhs_of(v: &Value) -> Option<String> {
    accounts::rhs_number(v)
}

/// What an `rhs_account_number` names: one account (its number,
/// designation, and whether it is the login's default), or `None` when two listed accounts share the reference —
/// an ambiguous join is left unattributed, never resolved to whichever
/// account came last.
pub type RhsMap = HashMap<String, Option<(String, Option<String>, bool)>>;

/// `rhs_account_number` → account, from the accounts listing. Pure.
pub fn rhs_map(rows: &[(String, Value)]) -> RhsMap {
    let mut map = RhsMap::new();
    for (n, r) in rows {
        if let Some(rhs) = accounts::rhs_number(r) {
            map.entry(rhs).and_modify(|e| *e = None).or_insert_with(|| {
                Some((n.clone(), accounts::designation(r), accounts::is_default(r)))
            });
        }
    }
    map
}

/// An instrument id as the wire should carry it: a bare UUID. Anything else
/// is dropped before it can reach a URL that carries the bearer token.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// A leg's instrument id, only when it is UUID-shaped.
fn instrument_id_of(v: &Value) -> Option<String> {
    str_at(v, "instrument_id").filter(|id| is_uuid(id))
}

fn instrument_url(id: &str) -> String {
    format!("{API_BASE}/instruments/{id}/")
}

/// The transfer's date: settlement, else requested.
fn transfer_date(v: &Value) -> Option<String> {
    str_at(v, "settlement_date").or_else(|| date_of(v, "requested_at"))
}

impl AcatsTransfer {
    pub fn from_json(
        v: &Value,
        by_rhs: &RhsMap,
        symbols: &HashMap<String, String>,
    ) -> Option<Self> {
        let id = str_at(v, "id")?;
        let rhs = rhs_of(v);
        let joined = rhs
            .as_ref()
            .and_then(|r| by_rhs.get(r))
            .and_then(Option::as_ref);
        let state = str_at(v, "phase");
        let settlement_date = str_at(v, "settlement_date");
        Some(AcatsTransfer {
            id,
            date: transfer_date(v),
            direction: str_at(v, "direction"),
            transfer_type: str_at(v, "transfer_type"),
            requested: date_of(v, "requested_at"),
            estimated_settlement_date: if settlement_date.is_none() {
                str_at(v, "estimated_settlement_date")
            } else {
                None
            },
            settlement_date,
            account_number: joined.map(|(n, _, _)| n.clone()),
            account_kind: joined.and_then(|(_, k, _)| k.clone()),
            account_default: joined.and_then(|(_, _, d)| d.then_some(true)),
            rhs_account_number: if joined.is_none() { rhs } else { None },
            contra_broker: str_at(v, "contra_broker_name"),
            contra_dtcc_number: str_at(v, "contra_dtcc_number"),
            reject_reason: if state.as_deref() == Some("rejected") {
                str_at(v, "reject_reason")
            } else {
                None
            },
            state,
            assets: v
                .get("assets")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|x| AcatsAsset::from_json(x, symbols))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// Keep the rows in range, newest first. An undated row is kept — silently
/// losing a transfer is the worse failure. `--limit` is applied by
/// [`select`], after the account filter, so `-a X --limit N` means "X's N
/// newest".
fn keep<'a>(rows: &'a [Value], range: &RangeArgs) -> Vec<&'a Value> {
    let mut kept: Vec<&Value> = rows
        .iter()
        .filter(|r| match transfer_date(r) {
            Some(d) => date_within(&d, range.since.as_deref(), range.until.as_deref()),
            None => true,
        })
        .collect();
    kept.sort_by_key(|r| std::cmp::Reverse(transfer_date(r)));
    kept
}

/// Narrow joined transfers to one account, when one is selected, then apply
/// `--limit`. Pure.
fn select(
    mut items: Vec<AcatsTransfer>,
    account: Option<&str>,
    limit: Option<u32>,
) -> Vec<AcatsTransfer> {
    if let Some(acct) = account {
        items.retain(|t| t.account_number.as_deref() == Some(acct));
    }
    if let Some(n) = limit {
        items.truncate(n as usize);
    }
    items
}

/// The equity legs' instruments, as the URL-keyed rows the batched symbol
/// resolver reads.
fn instrument_rows(rows: &[&Value]) -> Vec<Value> {
    rows.iter()
        .filter_map(|r| r.get("assets").and_then(Value::as_array))
        .flatten()
        .filter_map(instrument_id_of)
        .map(|id| serde_json::json!({ "instrument": instrument_url(&id) }))
        .collect()
}

/// Join a listing to the accounts and symbols. Pure.
pub fn join(
    rows: &[&Value],
    by_rhs: &RhsMap,
    symbols: &HashMap<String, String>,
) -> Vec<AcatsTransfer> {
    rows.iter()
        .filter_map(|r| AcatsTransfer::from_json(r, by_rhs, symbols))
        .collect()
}

pub fn acats(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    let token = ctx.access_token()?;
    let rows = ctx.rh.paginate_at(
        BONFIRE_BASE,
        &token,
        ACATS_PATH,
        &[("both_directions", "true".to_string())],
        None,
    )?;
    let kept = keep(&rows, range);

    let by_rhs = rhs_map(&accounts::addressable_rows(ctx, &token)?);
    let inst = instrument_rows(&kept);
    let inst_refs: Vec<&Value> = inst.iter().collect();
    let symbols = crate::commands::instruments::resolve_symbols(ctx, &token, &inst_refs)?;

    let items = select(
        join(&kept, &by_rhs, &symbols),
        ctx.account.as_deref(),
        range.limit,
    );

    let page = Paged::new("acats-transfer", items);
    if ctx.common.json {
        page.emit(true);
    } else {
        let v = serde_json::to_value(&page).unwrap_or(Value::Null);
        let mut rows = output::rows_of(&v, "items");
        for (row, item) in rows.iter_mut().zip(&page.items) {
            row["assets"] = Value::String(assets_summary(&item.assets));
        }
        output::table(&rows);
    }
    Ok(())
}

/// The legs in one line: `10 SAMPL, 1 ?, cash +19.69 USD`.
fn assets_summary(assets: &[AcatsAsset]) -> String {
    assets
        .iter()
        .map(|a| {
            let q = a.quantity.as_deref().unwrap_or("?");
            match a.asset_type.as_deref() {
                Some("cash") => {
                    let sign = if a.direction.as_deref() == Some("short") {
                        "-"
                    } else {
                        "+"
                    };
                    format!("cash {sign}{q} {}", a.currency.as_deref().unwrap_or(""))
                        .trim_end()
                        .to_string()
                }
                _ => format!("{q} {}", a.symbol.as_deref().unwrap_or("?")),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/acats_transfers.json"
        ))
        .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn accounts_fixture() -> Vec<(String, Value)> {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/accounts.json"
        ))
        .unwrap();
        let v: Value = serde_json::from_str(&raw).unwrap();
        v["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| str_at(r, "account_number").map(|n| (n, r.clone())))
            .collect()
    }

    fn symbols() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(
            instrument_url("00000000-0000-4000-8000-0000000000a1"),
            "SAMPL".to_string(),
        );
        m
    }

    fn joined() -> Vec<AcatsTransfer> {
        let f = fixture();
        let rows: Vec<Value> = f["results"].as_array().unwrap().clone();
        let range = RangeArgs::default();
        let kept = keep(&rows, &range);
        join(&kept, &rhs_map(&accounts_fixture()), &symbols())
    }

    #[test]
    fn transfers_join_their_account_through_the_rhs_number() {
        let t = joined();
        // Newest first by transfer date.
        let dates: Vec<_> = t.iter().map(|x| x.date.clone().unwrap()).collect();
        let mut sorted = dates.clone();
        sorted.sort();
        sorted.reverse();
        assert_eq!(dates, sorted);

        // The legacy default account: its rhs number differs from its
        // alphanumeric account number, and the join still finds it.
        let full = t
            .iter()
            .find(|x| {
                x.transfer_type.as_deref() == Some("full") && x.state.as_deref() == Some("settled")
            })
            .unwrap();
        assert_eq!(full.account_number.as_deref(), Some("SAMPLE01"));
        assert_eq!(full.account_kind.as_deref(), Some("individual"));
        assert!(full.rhs_account_number.is_none());
        // The default account says so, as the `--all-accounts` reads do.
        assert_eq!(full.account_default, Some(true));
        let v = serde_json::to_value(full).unwrap();
        assert_eq!(v["account_default"], true);
        assert_eq!(full.contra_broker.as_deref(), Some("Example Securities"));
        // A settled row's support-link `reject_reason` is noise, not a reason.
        assert!(full.reject_reason.is_none());
        assert!(full.estimated_settlement_date.is_none());
    }

    #[test]
    fn assets_resolve_symbols_and_keep_cash_legs() {
        let t = joined();
        let full = t
            .iter()
            .find(|x| {
                x.transfer_type.as_deref() == Some("full") && x.state.as_deref() == Some("settled")
            })
            .unwrap();
        let equity = &full.assets[0];
        assert_eq!(equity.asset_type.as_deref(), Some("equity"));
        assert_eq!(equity.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(equity.quantity.as_deref(), Some("10"));
        // An unresolved instrument omits the symbol rather than inventing one.
        assert!(full.assets[1].symbol.is_none());
        let cash: Vec<_> = full
            .assets
            .iter()
            .filter(|a| a.asset_type.as_deref() == Some("cash"))
            .collect();
        assert_eq!(cash[0].currency.as_deref(), Some("USD"));
        assert_eq!(cash[1].direction.as_deref(), Some("short"));
        assert_eq!(
            assets_summary(&full.assets),
            "10 SAMPL, 2 ?, cash +19.69 USD, cash -75 USD"
        );
    }

    #[test]
    fn a_rejected_transfer_keeps_its_reason_and_an_unknown_account_keeps_its_reference() {
        let t = joined();
        let rejected = t
            .iter()
            .find(|x| x.state.as_deref() == Some("rejected"))
            .unwrap();
        assert!(rejected.reject_reason.is_some());
        assert!(rejected.settlement_date.is_none());
        assert_eq!(
            rejected.estimated_settlement_date.as_deref(),
            Some("2024-03-08")
        );
        // Its rhs number matches no account in the login.
        assert!(rejected.account_number.is_none());
        assert_eq!(rejected.rhs_account_number.as_deref(), Some("900000009"));
    }

    #[test]
    fn no_cost_basis_is_ever_emitted() {
        let v = serde_json::to_value(Paged::new("acats-transfer", joined())).unwrap();
        assert_eq!(v["schema"], "acats-transfer-list/v1");
        assert!(!v.to_string().contains("basis"));
    }

    #[test]
    fn the_range_filters_on_the_transfer_date() {
        let f = fixture();
        let rows: Vec<Value> = f["results"].as_array().unwrap().clone();
        let range = RangeArgs {
            since: Some("2024-01-01".into()),
            ..RangeArgs::default()
        };
        let kept = keep(&rows, &range);
        assert_eq!(kept.len(), 1);
        assert_eq!(str_at(kept[0], "phase").as_deref(), Some("rejected"));
    }

    /// `-a X --limit N` is X's N newest: the account filter runs before the
    /// limit, so a newer transfer in another account cannot crowd X out.
    #[test]
    fn the_account_filter_runs_before_the_limit() {
        // The newest transfer (the rejected one) matches no account; the
        // selected account's newest is the residual sweep.
        let picked = select(joined(), Some("SAMPLE01"), Some(1));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].transfer_type.as_deref(), Some("residual"));
        assert_eq!(select(joined(), None, Some(1)).len(), 1);
        assert_eq!(select(joined(), None, None).len(), 3);
    }

    /// Two listed accounts sharing an rhs reference: the join is ambiguous,
    /// so the transfer stays unattributed with its reference kept, never
    /// silently given to whichever account came last.
    #[test]
    fn an_ambiguous_rhs_reference_is_left_unattributed() {
        let mut accts = accounts_fixture();
        let mut twin = accts[1].1.clone();
        twin["rhs_account_number"] = accts[0].1["rhs_account_number"].clone();
        accts.push(("SAMPLE07".into(), twin));
        let map = rhs_map(&accts);
        assert_eq!(map.get("100000001"), Some(&None));
        let f = fixture();
        let rows: Vec<Value> = f["results"].as_array().unwrap().clone();
        let kept = keep(&rows, &RangeArgs::default());
        let t = join(&kept, &map, &symbols());
        let full = t
            .iter()
            .find(|x| {
                x.transfer_type.as_deref() == Some("full") && x.state.as_deref() == Some("settled")
            })
            .unwrap();
        assert!(full.account_number.is_none());
        assert_eq!(full.rhs_account_number.as_deref(), Some("100000001"));
    }

    /// A transfer into a non-default account omits `account_default`, so
    /// the mark appears only where the `--all-accounts` reads put it.
    #[test]
    fn only_the_default_accounts_transfer_is_marked_default() {
        let f = fixture();
        let mut rows: Vec<Value> = f["results"].as_array().unwrap().clone();
        for row in &mut rows {
            row["rhs_account_number"] = serde_json::json!(100000005);
        }
        let kept = keep(&rows, &RangeArgs::default());
        let t = join(&kept, &rhs_map(&accounts_fixture()), &symbols());
        assert!(t
            .iter()
            .all(|x| x.account_number.as_deref() == Some("SAMPLE05")));
        assert!(t.iter().all(|x| x.account_default.is_none()));
        let v = serde_json::to_value(&t[0]).unwrap();
        assert!(v.get("account_default").is_none());
    }

    /// A provider instrument id goes into a token-bearing URL, so only a
    /// UUID-shaped one is used.
    #[test]
    fn only_uuid_shaped_instrument_ids_are_used() {
        let leg = json!({"asset_type": "equity", "instrument_id": "../accounts/x"});
        assert!(instrument_id_of(&leg).is_none());
        assert!(instrument_rows(&[&json!({"assets": [leg]})]).is_empty());
        let ok = json!({"instrument_id": "00000000-0000-4000-8000-0000000000a1"});
        assert!(instrument_id_of(&ok).is_some());
    }

    #[test]
    fn the_rhs_number_reads_as_integer_or_string() {
        assert_eq!(
            rhs_of(&json!({"rhs_account_number": 123})).as_deref(),
            Some("123")
        );
        assert_eq!(
            rhs_of(&json!({"rhs_account_number": "123"})).as_deref(),
            Some("123")
        );
        assert_eq!(rhs_of(&json!({})), None);
    }
}
