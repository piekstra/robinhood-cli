//! `rhd transactions list` / `rhd transactions options` — the realized-gains
//! raw material, in a date range.
//!
//! # Why this is orders, and what it is not
//!
//! Robinhood exposes **no realized-gain endpoint and no unified transaction
//! ledger**. The community reconstructs cost basis by walking filled orders,
//! which is what this command group surfaces: the raw material for a
//! Schedule D / Form 8949 workup, not a computed gain.
//!
//! For actual tax figures the consolidated 1099 is the source of truth — see
//! `rhd documents`. Treating this list as if it were a realized-gain report
//! would be wrong in every case involving wash sales, corporate actions,
//! options assignment, or transferred-in lots.
//!
//! # Two feeds, because the provider splits them
//!
//! Equities `/orders/` does **not** include options activity; options orders
//! live at `/options/orders/` with a different shape (legs instead of an
//! instrument, premium instead of a share price). Hence two subcommands with
//! two DTOs — `transaction-list/v1` and `option-order-list/v1` — rather than
//! one list that would have to lie about half its columns.
//!
//! The options read is LIVE-VERIFIED (2026-08-24, docs/api.md §3.4.1). The
//! community sources it was built from disagree about whether a leg carries
//! its strike/expiry/type inline; live, legs arrived **inline**. This code
//! still reads inline first and falls back to resolving each leg's
//! option-instrument URL (deduplicated, paced), so either documented shape
//! produces a complete row if the provider reshapes the API.
//!
//! # The consumer contract (live-verified 2026-08-24, corrected 2026-10-02)
//!
//! Both feeds include `cancelled` and resting (`confirmed`) orders. Most
//! carry **no executed figures** — zero quantity, no notional, no premium —
//! but a `cancelled` row (and `partially_filled_rest_cancelled`) can hold a
//! **partial fill**: an executed quantity above zero with its executed
//! figure. That is order history, not data loss, so neither list
//! pre-filters. A downstream realized-gains consumer must count a row that
//! is `filled` or carries an executed quantity above zero — never filter
//! on `state == "filled"` alone, which drops the partial fills — and must
//! treat an **absent** `state` (omitted when the wire doesn't carry one) as
//! *unknown, inspect me*, never as "not filled": silently dropping such a
//! row is exactly the loss `keep_sorted`'s undated-row rule refuses.

use std::collections::{BTreeSet, HashMap};

use pk_cli_core::{output, CliError, Money, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use crate::commands::{
    date_of, fanout, money_any, money_at, money_obj_at, signed_by_direction, str_at, trim_quantity,
    Ctx,
};

pub const PATH: &str = "/orders/";
pub const OPTIONS_PATH: &str = "/options/orders/";

/// One execution (fill) inside an order — shared by the equity and options
/// DTOs, because the wire shape is the same in both places.
#[derive(Debug, Serialize)]
pub struct Execution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

impl Execution {
    fn from_json(v: &Value) -> Self {
        Execution {
            price: money_at(v, "price"),
            quantity: str_at(v, "quantity").map(|q| trim_quantity(&q)),
            settlement_date: str_at(v, "settlement_date"),
            timestamp: str_at(v, "timestamp"),
        }
    }

    fn list_at(v: &Value, key: &str) -> Option<Vec<Execution>> {
        let arr = v.get(key)?.as_array()?;
        Some(arr.iter().map(Execution::from_json).collect())
    }
}

/// One equity order (`transaction/v1`).
///
/// The 2026-08 enrichment (`executed_notional`, `fees`, `executions`) is
/// **additive within v1** per the family DTO-evolution rule: every new field
/// is optional and omitted when absent, so older consumers see exactly the
/// payload they always did.
#[derive(Debug, Serialize)]
pub struct Transaction {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// The equity instrument's UUID (out of the order's `instrument` URL),
    /// carried even when the symbol resolved, so a row whose symbol did not
    /// can still be looked up (`rhd api GET /instruments/<id>/`). A bare id,
    /// like the option DTOs' `option_id`; `position/v1` keeps the whole
    /// `instrument` URL, which it carried before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    /// The price actually achieved, which is what basis work needs — not the
    /// limit price the order was placed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_price: Option<Money>,
    /// Executed dollar amount, from the wire's nested `executed_notional`
    /// money object. Null until something fills (and on the wire's own
    /// cancelled rows), so absent rather than $0 here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_notional: Option<Money>,
    /// Regulatory fees, a flat string on the wire (`"0.02"`). Surfaced
    /// because a basis workup that ignores fees overstates the proceeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The account the order belongs to — the wire's `account_number`, else
    /// the number in its `account` URL (live order rows carry only the URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    /// The account's designation (`individual`, `ira_roth`, …), tagged by
    /// `--all-accounts` (docs/api.md §3.14).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_kind: Option<String>,
    /// `true` on a row from the login's default account under
    /// `--all-accounts`; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_default: Option<bool>,
    /// Per-fill detail, opt-in via `--executions` — settlement dates matter
    /// for year-boundary trades, but most reads don't need the noise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executions: Option<Vec<Execution>>,
}

impl Transaction {
    fn from_json(v: &Value, symbols: &HashMap<String, String>, executions: bool) -> Option<Self> {
        let id = str_at(v, "id")?;
        Some(Transaction {
            id,
            // `last_transaction_at` is when it actually executed; `created_at`
            // is when it was placed. For tax work the execution date is the
            // one that matters, so prefer it and fall back.
            date: order_date(v),
            symbol: str_at(v, "instrument")
                .as_deref()
                .and_then(|u| symbols.get(u))
                .cloned()
                .or_else(|| str_at(v, "chain_symbol")),
            instrument_id: str_at(v, "instrument")
                .as_deref()
                .and_then(crate::commands::instrument_id),
            side: str_at(v, "side"),
            quantity: str_at(v, "cumulative_quantity")
                .or_else(|| str_at(v, "quantity"))
                .map(|q| trim_quantity(&q)),
            average_price: money_at(v, "average_price"),
            executed_notional: money_obj_at(v, "executed_notional"),
            fees: money_at(v, "fees"),
            state: str_at(v, "state"),
            account_number: fanout::row_account(v),
            account_kind: fanout::kind_of(v),
            account_default: fanout::default_of(v),
            executions: if executions {
                Execution::list_at(v, "executions")
            } else {
                None
            },
        })
    }
}

/// Read an order feed (`path`): one scoped read per account under
/// `--all-accounts`, every row verified and tagged (docs/api.md §3.14);
/// otherwise one read scoped to the selected account, if any.
fn read_orders(
    ctx: &Ctx,
    token: &str,
    path: &str,
    range: &RangeArgs,
    all_accounts: bool,
    what: &str,
) -> Result<Vec<Value>, CliError> {
    if all_accounts {
        // History reads include closed accounts: one can hold this year's
        // trades.
        fanout::read_all(ctx, token, false, what, |s| {
            ctx.rh
                .paginate(token, path, &order_query(Some(&s.number), range), None)
        })
    } else {
        ctx.rh.paginate(
            token,
            path,
            &order_query(ctx.account.as_deref(), range),
            None,
        )
    }
}

pub fn list(
    ctx: &Ctx,
    range: &RangeArgs,
    executions: bool,
    all_accounts: bool,
) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    let rows = read_orders(ctx, &token, PATH, range, all_accounts, "order")?;
    let kept = keep_sorted(&rows, range, order_date);

    let symbols = crate::commands::instruments::resolve_symbols(ctx, &token, &kept)?;
    let items: Vec<Transaction> = kept
        .iter()
        .filter_map(|r| Transaction::from_json(r, &symbols, executions))
        .collect();

    Paged::new("transaction", items).emit(ctx.common.json);
    Ok(())
}

/// The server-side query both order endpoints share: `account_numbers` and the
/// `updated_at[gte]` date floor (there is no `lte` counterpart, so `--until`
/// stays client-side).
///
/// Without `account_numbers` both feeds answer for the login's **default**
/// account only (docs/api.md §3.4) — never "every account".
fn order_query(account: Option<&str>, range: &RangeArgs) -> Vec<(&'static str, String)> {
    let mut query: Vec<(&'static str, String)> = Vec::new();
    if let Some(acct) = account {
        query.push(("account_numbers", acct.to_string()));
    }
    if let Some(since) = &range.since {
        // Server-side bound, so a multi-year account doesn't page its whole
        // history just to answer "this tax year".
        query.push(("updated_at[gte]", format!("{since}T00:00:00Z")));
    }
    query
}

/// Filter to the requested range, sort newest-first by `date_fn`, and apply
/// `--limit` — the post-fetch pipeline both order lists share.
///
/// Rows with no readable date are kept: dropping them would silently lose
/// orders, which is the worse failure for tax work. Sorting is by execution
/// date so `--limit N` means "the N most recent" rather than trusting the
/// server's (updated_at) ordering.
fn keep_sorted<'a>(
    rows: &'a [Value],
    range: &RangeArgs,
    date_fn: fn(&Value) -> Option<String>,
) -> Vec<&'a Value> {
    let mut kept: Vec<&Value> = rows
        .iter()
        .filter(|r| match date_fn(r) {
            Some(d) => {
                crate::commands::date_within(&d, range.since.as_deref(), range.until.as_deref())
            }
            // Undated rows are kept rather than silently dropped.
            None => true,
        })
        .collect();
    kept.sort_by_key(|r| std::cmp::Reverse(date_fn(r)));
    if let Some(n) = range.limit {
        kept.truncate(n as usize);
    }
    kept
}

/// Execution date, falling back to placement date — the same precedence
/// `from_json` uses for the DTO's `date`.
fn order_date(row: &Value) -> Option<String> {
    date_of(row, "last_transaction_at").or_else(|| date_of(row, "created_at"))
}

// --------------------------------------------------------------------------
// Options orders — `rhd transactions options` (LIVE-VERIFIED 2026-08-24)
// --------------------------------------------------------------------------

/// One leg of an options order.
///
/// Community sources disagree on this shape (docs/api.md §3.4.1): captured
/// responses carry only an `option` instrument URL, while a 2024+ community
/// model parses `expiration_date`/`strike_price`/`option_type` inline —
/// which is what the live wire did on 2026-08-24. The mapping reads the
/// inline fields when present; `list_options` still resolves the instrument
/// URL for legs that lack them, so either shape yields the
/// strike/expiry/type a P/L workup needs.
#[derive(Debug, Serialize)]
pub struct OptionLeg {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    /// `open` | `close` — the field that separates opening premium from
    /// closing premium in a round trip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_effect: Option<String>,
    /// `call` | `put`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strike_price: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratio_quantity: Option<u64>,
    /// The option instrument's UUID, kept as the join key for anything deeper
    /// (`rhd api GET /options/instruments/<id>/`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executions: Option<Vec<Execution>>,
}

impl OptionLeg {
    fn from_json(v: &Value, resolved: &HashMap<String, Value>, executions: bool) -> Self {
        // Inline first; a resolved instrument fills only what is missing, so
        // the wire's own word always wins where both exist.
        let instrument = str_at(v, "option").and_then(|u| resolved.get(&u));
        let inst_field = |key: &str| instrument.and_then(|i| str_at(i, key));
        OptionLeg {
            side: str_at(v, "side"),
            position_effect: str_at(v, "position_effect"),
            // The inline key is `option_type`; the instrument's is `type`.
            option_type: str_at(v, "option_type").or_else(|| inst_field("type")),
            strike_price: money_any(v, "strike_price")
                .or_else(|| instrument.and_then(|i| money_any(i, "strike_price"))),
            expiration_date: str_at(v, "expiration_date").or_else(|| inst_field("expiration_date")),
            ratio_quantity: v.get("ratio_quantity").and_then(Value::as_u64),
            option_id: str_at(v, "option")
                .as_deref()
                .and_then(crate::commands::instrument_id),
            executions: if executions {
                Execution::list_at(v, "executions")
            } else {
                None
            },
        }
    }

    /// Whether the three descriptive fields all arrived inline — if not, the
    /// leg's instrument URL needs resolving.
    fn described_inline(v: &Value) -> bool {
        str_at(v, "option_type").is_some()
            && v.get("strike_price").map(is_scalar_value).unwrap_or(false)
            && str_at(v, "expiration_date").is_some()
    }
}

fn is_scalar_value(v: &Value) -> bool {
    v.is_string() || v.is_number()
}

/// One options order (`option-order/v1`).
#[derive(Debug, Serialize)]
pub struct OptionOrder {
    pub id: String,
    /// Latest fill timestamp across the legs, falling back to `updated_at`
    /// then `created_at` — options orders carry no `last_transaction_at`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// The underlying's ticker (`chain_symbol` — carried directly, unlike
    /// equity orders, so no instrument resolution is needed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// `debit` (cash out) | `credit` (cash in).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// Contracts actually executed (`processed_quantity`), falling back to
    /// the requested `quantity`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    /// Per-share premium (the wire's order-level `price`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<Money>,
    /// Total premium actually processed, **signed by cash flow**: positive
    /// for a `credit` (premium received), negative for a `debit` (premium
    /// paid). The wire carries an unsigned magnitude plus `direction`; both
    /// are surfaced so the signing is checkable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_premium: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opening_strategy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closing_strategy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    /// Tagged by `--all-accounts` (docs/api.md §3.14).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_kind: Option<String>,
    /// `true` on a row from the login's default account under
    /// `--all-accounts`; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_default: Option<bool>,
    pub legs: Vec<OptionLeg>,
}

impl OptionOrder {
    fn from_json(v: &Value, resolved: &HashMap<String, Value>, executions: bool) -> Option<Self> {
        let id = str_at(v, "id")?;
        Some(OptionOrder {
            id,
            date: option_order_date(v),
            symbol: str_at(v, "chain_symbol"),
            state: str_at(v, "state"),
            direction: str_at(v, "direction"),
            quantity: str_at(v, "processed_quantity")
                .or_else(|| str_at(v, "quantity"))
                .map(|q| trim_quantity(&q)),
            price: money_at(v, "price"),
            processed_premium: signed_by_direction(v, "processed_premium"),
            opening_strategy: str_at(v, "opening_strategy"),
            closing_strategy: str_at(v, "closing_strategy"),
            account_number: fanout::row_account(v),
            account_kind: fanout::kind_of(v),
            account_default: fanout::default_of(v),
            legs: v
                .get("legs")
                .and_then(Value::as_array)
                .map(|legs| {
                    legs.iter()
                        .map(|l| OptionLeg::from_json(l, resolved, executions))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

/// Execution date for an options order: the latest fill timestamp across the
/// legs (RFC 3339 strings compare correctly as strings), then `updated_at`,
/// then `created_at`.
fn option_order_date(v: &Value) -> Option<String> {
    let latest_fill = v
        .get("legs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|leg| leg.get("executions").and_then(Value::as_array))
        .flatten()
        .filter_map(|e| str_at(e, "timestamp"))
        .max();
    latest_fill
        .map(|t| t.split('T').next().unwrap_or(&t).to_string())
        .filter(|d| d.len() == 10)
        .or_else(|| date_of(v, "updated_at"))
        .or_else(|| date_of(v, "created_at"))
}

pub fn list_options(
    ctx: &Ctx,
    range: &RangeArgs,
    executions: bool,
    all_accounts: bool,
) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    // Same server-side query the equity endpoint takes (`account_numbers`,
    // `updated_at[gte]`) — live-verified 2026-08-24: narrow ranges returned
    // scoped result sets quickly (docs/api.md §3.4.1). The client-side
    // re-filter below stays anyway: there is no `lte` counterpart, and the
    // server honoring the parameter is an observation, not a contract.
    let rows = read_orders(
        ctx,
        &token,
        OPTIONS_PATH,
        range,
        all_accounts,
        "option order",
    )?;
    let kept = keep_sorted(&rows, range, option_order_date);

    let resolved = resolve_option_instruments(&ctx.rh, ctx.common.quiet, &token, &kept)?;
    let items: Vec<OptionOrder> = kept
        .iter()
        .filter_map(|r| OptionOrder::from_json(r, &resolved, executions))
        .collect();

    let page = Paged::new("option-order", items);
    if ctx.common.json {
        page.emit(true);
    } else {
        // The default table would render each leg as raw JSON. Same rows,
        // same fields — but legs summarized into option shorthand
        // ("sell-to-open $150.00C 2026-07-17") so the table stays readable.
        let v = serde_json::to_value(&page).unwrap_or(Value::Null);
        let mut rows = output::rows_of(&v, "items");
        for (row, item) in rows.iter_mut().zip(&page.items) {
            row["legs"] = Value::String(legs_summary(&item.legs));
        }
        output::table(&rows);
    }
    Ok(())
}

/// Fetch the option instruments for legs that did not arrive fully described
/// inline — deduplicated, and paced by the client's own 250 ms floor.
///
/// This runs only for the shape the older community captures show (legs
/// carrying just an `option` URL). Live (2026-08-24) the wire carried the
/// inline fields and this resolved nothing — which costs nothing — but it
/// stays as the fallback for the other documented shape, since the provider
/// reshapes this API without notice.
fn resolve_option_instruments(
    rh: &crate::client::Rh,
    quiet: bool,
    token: &str,
    rows: &[&Value],
) -> Result<HashMap<String, Value>, CliError> {
    let needed: BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r.get("legs").and_then(Value::as_array))
        .flatten()
        .filter(|leg| !OptionLeg::described_inline(leg))
        .filter_map(|leg| str_at(leg, "option"))
        .collect();

    // A leg's option URL is provider-supplied and is dereferenced with the
    // bearer token attached — the same rule as pagination cursors: never
    // follow one off the API origin. Checked for the whole set up front, so
    // a poisoned listing fails before the first request is spent, not after
    // hundreds.
    if let Some(bad) = needed.iter().find(|u| !rh.same_origin(u)) {
        return Err(CliError::Upstream(format!(
            "refusing to resolve an option instrument off the API origin: {bad}"
        )));
    }

    if !needed.is_empty() && !quiet {
        // Potentially hundreds of paced requests on an options-heavy year;
        // say so, or the wait looks like a hang.
        eprintln!(
            "resolving {} option contract(s) for strike/expiry/type detail \
             (paced ~4 req/s; narrow with --since/--limit to reduce)",
            needed.len()
        );
    }

    let mut resolved = HashMap::new();
    for url in needed {
        let v = rh.get(token, &url, &[])?;
        resolved.insert(url, v);
    }
    Ok(resolved)
}

/// Compact option shorthand for the text table: one clause per leg, `?` where
/// a piece is missing — a blank would hide that something failed to resolve.
fn legs_summary(legs: &[OptionLeg]) -> String {
    legs.iter()
        .map(|leg| {
            let ratio = match leg.ratio_quantity {
                Some(r) if r > 1 => format!("{r}x "),
                _ => String::new(),
            };
            let side = leg.side.as_deref().unwrap_or("?");
            let effect = leg.position_effect.as_deref().unwrap_or("?");
            let strike = leg
                .strike_price
                .as_ref()
                .map(|m| format!("${}", m.amount))
                .unwrap_or_else(|| "?".into());
            let t = match leg.option_type.as_deref() {
                Some("call") => "C",
                Some("put") => "P",
                Some(other) => other,
                None => "?",
            };
            let exp = leg.expiration_date.as_deref().unwrap_or("?");
            format!("{ratio}{side}-to-{effect} {strike}{t} {exp}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "id": "00000000-0000-4000-8000-000000000010",
            "account_number": "8UD09348",
            "instrument": "https://api.robinhood.com/instruments/00000000-0000-4000-8000-000000000001/",
            "side": "buy",
            "state": "filled",
            "quantity": "10.00000000",
            "cumulative_quantity": "10.00000000",
            "average_price": "150.0000",
            "price": "151.0000",
            "fees": "0.02",
            "total_notional": null,
            "executed_notional": {
                "amount": "1500.00",
                "currency_code": "USD",
                "currency_id": "00000000-0000-4000-8000-000000000099"
            },
            "created_at": "2026-03-14T13:30:00.000000Z",
            "last_transaction_at": "2026-03-14T13:31:02.000000Z",
            "executions": [
                {
                    "id": "00000000-0000-4000-8000-0000000000e1",
                    "price": "150.0000",
                    "quantity": "10.00000000",
                    "settlement_date": "2026-03-16",
                    "timestamp": "2026-03-14T13:31:02.000000Z"
                }
            ]
        })
    }

    /// Live order rows name their account by URL only (docs/api.md §3.4);
    /// the DTO still reports the account number, and no fan-out tags.
    #[test]
    fn the_account_number_falls_back_to_the_account_url() {
        let mut v = sample();
        v.as_object_mut().unwrap().remove("account_number");
        v["account"] = json!("https://api.robinhood.com/accounts/SAMPLE02/");
        let t = Transaction::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.account_number.as_deref(), Some("SAMPLE02"));
        assert!(t.account_kind.is_none());
        assert!(t.account_default.is_none());
    }

    /// The order query scopes by `account_numbers` only when an account is
    /// named — the fan-out passes each account in turn.
    #[test]
    fn the_order_query_scopes_by_the_named_account() {
        let range = RangeArgs::default();
        assert!(order_query(None, &range).is_empty());
        let q = order_query(Some("SAMPLE01"), &range);
        assert_eq!(q, vec![("account_numbers", "SAMPLE01".to_string())]);
    }

    #[test]
    fn prefers_the_execution_date_over_the_placement_date() {
        let mut v = sample();
        v["created_at"] = json!("2026-03-13T23:59:00.000000Z");
        let t = Transaction::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.date.as_deref(), Some("2026-03-14"));
    }

    #[test]
    fn falls_back_to_the_placement_date() {
        let mut v = sample();
        v.as_object_mut().unwrap().remove("last_transaction_at");
        let t = Transaction::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.date.as_deref(), Some("2026-03-14"));
    }

    #[test]
    fn uses_the_achieved_price_not_the_limit_price() {
        let t = Transaction::from_json(&sample(), &HashMap::new(), false).unwrap();
        let v = serde_json::to_value(&t).unwrap();
        // 150 is average_price; 151 was the limit price and must not appear.
        assert_eq!(v["average_price"]["amount"], "150.00");
    }

    /// The realized-gains feed needs the executed dollar amount and the fees;
    /// both come off the wire, not from client-side arithmetic.
    #[test]
    fn surfaces_the_executed_notional_and_fees() {
        let t = Transaction::from_json(&sample(), &HashMap::new(), false).unwrap();
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["executed_notional"]["amount"], "1500.00");
        assert_eq!(v["executed_notional"]["currency"], "USD");
        assert_eq!(v["fees"]["amount"], "0.02");
    }

    /// The enrichment must stay additive within `transaction/v1`: absent on
    /// the wire means absent in the DTO — never null noise — so pre-existing
    /// consumers see exactly the payload they always did.
    #[test]
    fn enrichment_fields_are_omitted_when_the_wire_lacks_them() {
        let mut v = sample();
        let obj = v.as_object_mut().unwrap();
        obj.remove("executed_notional");
        obj.remove("fees");
        let t = Transaction::from_json(&v, &HashMap::new(), false).unwrap();
        let v = serde_json::to_value(&t).unwrap();
        assert!(v.get("executed_notional").is_none());
        assert!(v.get("fees").is_none());
        assert!(v.get("executions").is_none());
    }

    /// Per-fill detail is opt-in: absent by default, mapped when asked.
    #[test]
    fn executions_detail_is_included_only_on_request() {
        let without = Transaction::from_json(&sample(), &HashMap::new(), false).unwrap();
        assert!(without.executions.is_none());

        let with = Transaction::from_json(&sample(), &HashMap::new(), true).unwrap();
        let execs = with.executions.expect("executions requested");
        assert_eq!(execs.len(), 1);
        let v = serde_json::to_value(&execs[0]).unwrap();
        assert_eq!(v["price"]["amount"], "150.00");
        assert_eq!(v["quantity"], "10");
        assert_eq!(v["settlement_date"], "2026-03-16");
    }

    #[test]
    fn range_filtering_is_inclusive_on_both_ends() {
        let rows = vec![sample()];
        let range = |s: &str, u: &str| RangeArgs {
            since: Some(s.into()),
            until: Some(u.into()),
            limit: None,
        };
        assert_eq!(
            keep_sorted(&rows, &range("2026-03-14", "2026-03-14"), order_date).len(),
            1
        );
        assert_eq!(
            keep_sorted(&rows, &range("2026-01-01", "2026-12-31"), order_date).len(),
            1
        );
        assert_eq!(
            keep_sorted(&rows, &range("2026-03-15", "2026-12-31"), order_date).len(),
            0
        );
        assert_eq!(
            keep_sorted(&rows, &range("2026-01-01", "2026-03-13"), order_date).len(),
            0
        );
    }

    /// Losing an order silently is the worst outcome for tax work, so a row
    /// we can't date is kept rather than filtered away.
    #[test]
    fn undated_rows_survive_filtering() {
        let rows = vec![json!({"id": "x"})];
        let range = RangeArgs {
            since: Some("2026-01-01".into()),
            until: Some("2026-12-31".into()),
            limit: None,
        };
        assert_eq!(keep_sorted(&rows, &range, order_date).len(), 1);
    }

    #[test]
    fn an_options_order_in_the_equity_feed_uses_its_chain_symbol() {
        let v = json!({
            "id": "opt-1",
            "chain_symbol": "SAMPL",
            "state": "filled",
            "created_at": "2026-05-01T10:00:00.000000Z"
        });
        let t = Transaction::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.symbol.as_deref(), Some("SAMPL"));
    }

    /// The instrument's id rides every row, resolved or not, so a row whose
    /// symbol did not resolve can still be looked up downstream.
    #[test]
    fn the_instrument_id_rides_the_row_with_or_without_a_symbol() {
        let url = sample()["instrument"].as_str().unwrap().to_string();
        let resolved = HashMap::from([(url, "SAMPL".to_string())]);
        for symbols in [resolved, HashMap::new()] {
            let t = Transaction::from_json(&sample(), &symbols, false).unwrap();
            assert_eq!(
                t.instrument_id.as_deref(),
                Some("00000000-0000-4000-8000-000000000001")
            );
        }
        let t = Transaction::from_json(&sample(), &HashMap::new(), false).unwrap();
        let v = serde_json::to_value(&t).unwrap();
        assert!(v.get("symbol").is_none(), "no symbol is invented");
        assert_eq!(v["instrument_id"], "00000000-0000-4000-8000-000000000001");
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new(
            "transaction",
            vec![Transaction::from_json(&sample(), &HashMap::new(), false).unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "transaction-list/v1");
        assert_eq!(v["items"][0]["side"], "buy");
    }

    // ------------------------------------------------------- options orders

    /// A sell-to-open credit order in the newer community shape: legs carry
    /// their strike/expiry/type inline.
    fn option_credit() -> Value {
        json!({
            "id": "00000000-0000-4000-8000-000000000050",
            "account_number": "SAMPLE01",
            "chain_symbol": "SAMPL",
            "state": "filled",
            "direction": "credit",
            "premium": "150.00000000",
            "processed_premium": "150.00000000",
            "price": "1.50000000",
            "quantity": "1.00000",
            "processed_quantity": "1.00000",
            "opening_strategy": "short_call",
            "closing_strategy": null,
            "created_at": "2026-06-01T14:00:00.000000Z",
            "updated_at": "2026-06-01T14:00:05.000000Z",
            "legs": [
                {
                    "id": "00000000-0000-4000-8000-000000000051",
                    "option": "https://api.robinhood.com/options/instruments/00000000-0000-4000-8000-0000000000a1/",
                    "position_effect": "open",
                    "ratio_quantity": 1,
                    "side": "sell",
                    "option_type": "call",
                    "strike_price": "150.0000",
                    "expiration_date": "2026-07-17",
                    "executions": [
                        {
                            "id": "00000000-0000-4000-8000-0000000000e5",
                            "price": "1.50000000",
                            "quantity": "1.00000",
                            "settlement_date": "2026-06-02",
                            "timestamp": "2026-06-01T14:00:05.100000Z"
                        }
                    ]
                }
            ]
        })
    }

    #[test]
    fn a_credit_premium_stays_positive_and_a_debit_goes_negative() {
        let credit = OptionOrder::from_json(&option_credit(), &HashMap::new(), false).unwrap();
        assert_eq!(credit.processed_premium.as_ref().unwrap().amount, "150.00");

        let mut v = option_credit();
        v["direction"] = json!("debit");
        let debit = OptionOrder::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(debit.processed_premium.as_ref().unwrap().amount, "-150.00");
    }

    /// A zero premium (a cancelled order) must not grow a `-0.00` sign, and a
    /// missing direction must not invent one.
    #[test]
    fn zero_or_directionless_premium_is_left_unsigned() {
        let mut v = option_credit();
        v["direction"] = json!("debit");
        v["processed_premium"] = json!("0.00");
        let t = OptionOrder::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.processed_premium.as_ref().unwrap().amount, "0.00");

        let mut v = option_credit();
        v.as_object_mut().unwrap().remove("direction");
        let t = OptionOrder::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.processed_premium.as_ref().unwrap().amount, "150.00");
    }

    #[test]
    fn legs_map_their_inline_descriptions() {
        let t = OptionOrder::from_json(&option_credit(), &HashMap::new(), false).unwrap();
        assert_eq!(t.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(t.quantity.as_deref(), Some("1"));
        let leg = &t.legs[0];
        assert_eq!(leg.side.as_deref(), Some("sell"));
        assert_eq!(leg.position_effect.as_deref(), Some("open"));
        assert_eq!(leg.option_type.as_deref(), Some("call"));
        assert_eq!(leg.strike_price.as_ref().unwrap().amount, "150.00");
        assert_eq!(leg.expiration_date.as_deref(), Some("2026-07-17"));
        assert_eq!(
            leg.option_id.as_deref(),
            Some("00000000-0000-4000-8000-0000000000a1")
        );
        // Executions not requested.
        assert!(leg.executions.is_none());
    }

    /// The older community shape: a leg carrying only its `option` URL. The
    /// description then comes from the resolved instrument — whose type key
    /// is `type`, not `option_type`.
    #[test]
    fn a_bare_leg_is_described_by_its_resolved_instrument() {
        let mut v = option_credit();
        let leg = &mut v["legs"][0];
        let obj = leg.as_object_mut().unwrap();
        obj.remove("option_type");
        obj.remove("strike_price");
        obj.remove("expiration_date");
        assert!(!OptionLeg::described_inline(&v["legs"][0]));

        let mut resolved = HashMap::new();
        resolved.insert(
            "https://api.robinhood.com/options/instruments/00000000-0000-4000-8000-0000000000a1/"
                .to_string(),
            json!({
                "id": "00000000-0000-4000-8000-0000000000a1",
                "type": "call",
                "strike_price": "150.0000",
                "expiration_date": "2026-07-17"
            }),
        );
        let t = OptionOrder::from_json(&v, &resolved, false).unwrap();
        let leg = &t.legs[0];
        assert_eq!(leg.option_type.as_deref(), Some("call"));
        assert_eq!(leg.strike_price.as_ref().unwrap().amount, "150.00");
        assert_eq!(leg.expiration_date.as_deref(), Some("2026-07-17"));
    }

    /// One community model reads strike prices as JSON numbers; the mapping
    /// must take either without ever touching a float.
    #[test]
    fn a_numeric_strike_price_still_maps() {
        let mut v = option_credit();
        v["legs"][0]["strike_price"] = json!(152.5);
        let t = OptionOrder::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(t.legs[0].strike_price.as_ref().unwrap().amount, "152.50");
    }

    /// The DTO's `date` is the latest fill across the legs — not the order's
    /// `updated_at`, which moves on any state change.
    #[test]
    fn the_order_date_is_the_latest_fill_timestamp() {
        let mut v = option_credit();
        v["updated_at"] = json!("2026-06-03T09:00:00.000000Z");
        assert_eq!(option_order_date(&v).as_deref(), Some("2026-06-01"));

        // No executions → fall back to updated_at.
        v["legs"][0]["executions"] = json!([]);
        assert_eq!(option_order_date(&v).as_deref(), Some("2026-06-03"));
    }

    #[test]
    fn the_options_envelope_is_tagged() {
        let page = Paged::new(
            "option-order",
            vec![OptionOrder::from_json(&option_credit(), &HashMap::new(), false).unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "option-order-list/v1");
        assert_eq!(v["items"][0]["direction"], "credit");
        assert_eq!(v["items"][0]["legs"][0]["side"], "sell");
    }

    /// The resolver dereferences provider-supplied URLs with the bearer token
    /// attached, so an off-origin one must be refused — before any request is
    /// spent, which is also what makes this testable offline: the guard runs
    /// ahead of all network I/O.
    #[test]
    fn an_off_origin_option_url_is_refused_before_any_request() {
        let rh = crate::client::Rh::new().unwrap();
        let row = json!({
            "legs": [{
                "option": "https://api.robinhood.com.evil.example/options/instruments/x/",
                "side": "sell"
            }]
        });
        let err = resolve_option_instruments(&rh, true, "token", &[&row]).unwrap_err();
        assert_eq!(err.exit_code(), 5, "upstream refusal, not a skip: {err}");
        assert!(err.to_string().contains("origin"), "{err}");
    }

    /// Fully-described legs need no resolution — the resolver must collect
    /// nothing (and therefore touch no network) for the inline shape.
    #[test]
    fn described_legs_are_not_collected_for_resolution() {
        let rh = crate::client::Rh::new().unwrap();
        let row = option_credit();
        let resolved = resolve_option_instruments(&rh, true, "token", &[&row]).unwrap();
        assert!(resolved.is_empty());
    }

    /// The table shorthand: complete legs read as option lingo; missing
    /// pieces surface as `?` rather than disappearing.
    #[test]
    fn the_leg_summary_is_loud_about_missing_detail() {
        let t = OptionOrder::from_json(&option_credit(), &HashMap::new(), false).unwrap();
        assert_eq!(legs_summary(&t.legs), "sell-to-open $150.00C 2026-07-17");

        let mut v = option_credit();
        let obj = v["legs"][0].as_object_mut().unwrap();
        obj.remove("option_type");
        obj.remove("strike_price");
        let t = OptionOrder::from_json(&v, &HashMap::new(), false).unwrap();
        assert_eq!(legs_summary(&t.legs), "sell-to-open ?? 2026-07-17");
    }
}
