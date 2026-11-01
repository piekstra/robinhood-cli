//! `rhd transactions option-events` — exercises, assignments and
//! expirations: the option activity that never appears in either order feed.
//!
//! An assigned short call delivers shares out of the account; an exercised
//! long call brings shares in; an expiration closes a contract for nothing.
//! None of these is an order, so `/orders/` and `/options/orders/` both stay
//! silent about them, and a realized-gains workup built on the order feeds
//! alone is left holding share lots that are gone and option lots that
//! ended. This read fills that gap.
//!
//! Two reads, both LIVE-VERIFIED 2026-10-02 (docs/api.md §3.10):
//!
//! 1. `GET /options/events/` — one row per event. It carries the event
//!    `type`, `event_date`, contract `quantity`, the share leg
//!    (`equity_components[]`: symbol, side, quantity, per-share price) and
//!    the cash (`total_cash_amount` + `direction`). **It carries no
//!    underlying ticker, strike, call/put or expiry** — only the option
//!    instrument's id.
//! 2. `GET /options/instruments/?ids=` — the same batched read
//!    `options positions` uses, to describe each contract.
//!
//! The traps (docs/api.md §3.10): `total_cash_amount` on an assignment is
//! **net of the sale's regulatory fees**, so it is a few cents short of
//! quantity × price; on an expiration it is a bare `"0"`; and nothing on
//! an expiration row says whether the contract was held long or short.

use std::collections::{BTreeSet, HashMap};

use pk_cli_core::{output, CliError, Money, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use crate::commands::option_instruments::{fetch_by_ids, option_id_of, INSTRUMENTS_PATH};
use crate::commands::{
    date_within, fanout, money_any, money_at, signed_by_direction, str_at, trim_quantity, Ctx,
};

pub const PATH: &str = "/options/events/";

/// The share leg of an exercise or assignment (`equity_components[]`).
#[derive(Debug, Serialize)]
pub struct ShareDelivery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// `buy` (shares received) | `sell` (shares delivered).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    /// Shares, unsigned (`side` carries the direction).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    /// Per-share price the shares moved at — the strike, live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<Money>,
}

impl ShareDelivery {
    fn from_json(v: &Value) -> Self {
        ShareDelivery {
            symbol: str_at(v, "symbol"),
            side: str_at(v, "side"),
            quantity: str_at(v, "quantity").map(|q| trim_quantity(&q)),
            price: money_at(v, "price"),
        }
    }
}

/// One option event (`option-event/v1`).
#[derive(Debug, Serialize)]
pub struct OptionEvent {
    pub id: String,
    /// The event's day (`event_date`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// `exercise` | `assignment` | `expiration` (the wire's `type`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Every live row was `confirmed`; see docs/api.md §3.10.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// The underlying's ticker, from the option instrument (`chain_symbol`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// `call` | `put` — from the option instrument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strike_price: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    /// Shares per contract (`trade_value_multiplier`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplier: Option<String>,
    /// Contracts the event closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    /// `long` for an exercise (only a holder exercises), `short` for an
    /// assignment (only a writer is assigned). Absent for an expiration:
    /// the row does not say which side lapsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_type: Option<String>,
    /// `debit` (cash out) | `credit` (cash in).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// The event's cash, **signed by cash flow** like `transactions
    /// options`' premium: positive for a `credit`, negative for a `debit`.
    /// On an assignment it is net of the sale's fees; on an expiration zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cash_amount: Option<Money>,
    /// Cash settlement, when the contract settles in cash rather than
    /// shares (`cash_component`; null on every live row).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cash_component: Option<Money>,
    /// Shares moved by an exercise or assignment; empty for an expiration.
    pub deliveries: Vec<ShareDelivery>,
    /// The underlying's price at the event (sometimes null on the wire).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub underlying_price: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    /// Tagged by `--all-accounts` (docs/api.md §3.14).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_kind: Option<String>,
    /// `true` on a row from the login's default account under
    /// `--all-accounts`; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_default: Option<bool>,
    /// The option instrument's UUID — the join key to `options positions`
    /// and to `transactions options` legs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_id: Option<String>,
}

impl OptionEvent {
    /// Map one event row, described by its option instrument when one was
    /// resolved. `None` only for a row with no `id`.
    pub fn from_parts(v: &Value, inst: Option<&Value>) -> Option<Self> {
        let id = str_at(v, "id")?;
        let event_type = str_at(v, "type");
        let position_type = match event_type.as_deref() {
            Some("exercise") => Some("long".to_string()),
            Some("assignment") => Some("short".to_string()),
            _ => None,
        };
        let deliveries: Vec<ShareDelivery> = v
            .get("equity_components")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().map(ShareDelivery::from_json).collect())
            .unwrap_or_default();
        Some(OptionEvent {
            id,
            date: str_at(v, "event_date"),
            event_type,
            state: str_at(v, "state"),
            // The instrument names the underlying; a delivery's own symbol
            // stands in when the instrument did not resolve.
            symbol: inst
                .and_then(|i| str_at(i, "chain_symbol"))
                .or_else(|| deliveries.iter().find_map(|d| d.symbol.clone())),
            option_type: inst.and_then(|i| str_at(i, "type")),
            strike_price: inst.and_then(|i| money_at(i, "strike_price")),
            expiration_date: inst.and_then(|i| str_at(i, "expiration_date")),
            multiplier: inst
                .and_then(|i| str_at(i, "trade_value_multiplier"))
                .map(|m| trim_quantity(&m)),
            quantity: str_at(v, "quantity").map(|q| trim_quantity(&q)),
            position_type,
            direction: str_at(v, "direction"),
            cash_amount: signed_by_direction(v, "total_cash_amount"),
            cash_component: money_any(v, "cash_component"),
            deliveries,
            underlying_price: money_at(v, "underlying_price"),
            account_number: fanout::row_account(v),
            account_kind: fanout::kind_of(v),
            account_default: fanout::default_of(v),
            option_id: option_id_of(v),
        })
    }
}

/// Keep the rows in range and in the selected account, newest first, and
/// apply `--limit`. The endpoint takes no known date or account parameter,
/// so both filters are client-side. An undated row is kept: silently losing
/// an assignment is the worse failure for tax work. Under an account filter
/// a row naming no account is dropped — it cannot be attributed.
fn keep<'a>(rows: &'a [Value], range: &RangeArgs, account: Option<&str>) -> Vec<&'a Value> {
    let mut kept: Vec<&Value> = rows
        .iter()
        .filter(|r| match str_at(r, "event_date") {
            Some(d) => date_within(&d, range.since.as_deref(), range.until.as_deref()),
            None => true,
        })
        .filter(|r| match account {
            Some(a) => str_at(r, "account_number").as_deref() == Some(a),
            None => true,
        })
        .collect();
    kept.sort_by_key(|r| std::cmp::Reverse(str_at(r, "event_date")));
    if let Some(n) = range.limit {
        kept.truncate(n as usize);
    }
    kept
}

/// Join event rows to their instruments. Pure, so the mapping is pinned
/// offline against the fixtures.
pub fn join(rows: &[&Value], instruments: &HashMap<String, Value>) -> Vec<OptionEvent> {
    rows.iter()
        .filter_map(|r| {
            let inst = option_id_of(r).and_then(|id| instruments.get(&id));
            OptionEvent::from_parts(r, inst)
        })
        .collect()
}

pub fn list(ctx: &Ctx, range: &RangeArgs, all_accounts: bool) -> Result<(), CliError> {
    let token = ctx.access_token()?;
    let (rows, account) = if all_accounts {
        // `account_numbers` is what the provider's web app sends here; the
        // fan-out's per-row verification is what makes trusting it safe
        // (docs/api.md §3.14).
        let rows = fanout::read_all(ctx, &token, false, "option event", |s| {
            ctx.rh
                .paginate(&token, PATH, &[("account_numbers", s.number.clone())], None)
        })?;
        (rows, None)
    } else {
        (
            ctx.rh.paginate(&token, PATH, &[], None)?,
            ctx.account.as_deref(),
        )
    };
    let kept = keep(&rows, range, account);

    let ids: BTreeSet<String> = kept.iter().filter_map(|r| option_id_of(r)).collect();
    let instruments = if ids.is_empty() {
        HashMap::new()
    } else {
        fetch_by_ids(ctx, &token, INSTRUMENTS_PATH, &ids, "id")?
    };

    let items = join(&kept, &instruments);
    if !ctx.common.quiet {
        let undescribed = items
            .iter()
            .filter(|e| e.strike_price.is_none() || e.option_type.is_none())
            .count();
        if undescribed > 0 {
            eprintln!(
                "{undescribed} event(s) missing strike or call/put detail — the option \
                 instrument did not resolve"
            );
        }
    }

    let page = Paged::new("option-event", items);
    if ctx.common.json {
        page.emit(true);
    } else {
        output::table(&table_rows(&page.items));
    }
    Ok(())
}

/// The contract in option shorthand (`$40.00C 2026-10-16`), `?` where a
/// piece is missing.
fn contract(e: &OptionEvent) -> String {
    let strike = e
        .strike_price
        .as_ref()
        .map(|s| format!("${}", s.amount))
        .unwrap_or_else(|| "?".into());
    let t = match e.option_type.as_deref() {
        Some("call") => "C",
        Some("put") => "P",
        Some(other) => other,
        None => "?",
    };
    let exp = e.expiration_date.as_deref().unwrap_or("?");
    format!("{strike}{t} {exp}")
}

/// The share leg in one clause per delivery: `+200 SAMPL @ $40.00` for
/// shares received, `-100 SAMPL @ $50.00` for shares delivered.
fn deliveries_summary(e: &OptionEvent) -> String {
    e.deliveries
        .iter()
        .map(|d| {
            let sign = match d.side.as_deref() {
                Some("buy") => "+",
                Some("sell") => "-",
                _ => "?",
            };
            let price = d
                .price
                .as_ref()
                .map(|p| format!("${}", p.amount))
                .unwrap_or_else(|| "?".into());
            format!(
                "{sign}{} {} @ {price}",
                d.quantity.as_deref().unwrap_or("?"),
                d.symbol.as_deref().unwrap_or("?")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn table_rows(items: &[OptionEvent]) -> Vec<Value> {
    items
        .iter()
        .map(|e| {
            serde_json::json!({
                "date": e.date.as_deref().unwrap_or("?"),
                "event": e.event_type.as_deref().unwrap_or("?"),
                "symbol": e.symbol.as_deref().unwrap_or("?"),
                "contract": contract(e),
                "qty": e.quantity.as_deref().unwrap_or("?"),
                "shares": deliveries_summary(e),
                "cash": e.cash_amount.as_ref().map(|m| format!("${}", m.amount)),
                "account": e.account_number.as_deref().unwrap_or(""),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "00000000-0000-4000-8000-0000000000b3";

    fn exercise() -> Value {
        json!({
            "id": "00000000-0000-4000-8000-0000000000d1",
            "type": "exercise",
            "state": "confirmed",
            "direction": "debit",
            "event_date": "2026-10-16",
            "quantity": "2.0000",
            "total_cash_amount": "8000.00",
            "cash_component": null,
            "underlying_price": "41.5000",
            "account_number": "SAMPLE01",
            "option": format!("https://api.robinhood.com/options/instruments/{ID}/"),
            "option_id": ID,
            "equity_components": [{
                "id": "00000000-0000-4000-8000-0000000000e9",
                "instrument": "https://api.robinhood.com/instruments/00000000-0000-4000-8000-000000000001/",
                "price": "40.0000",
                "quantity": "200.00000000",
                "side": "buy",
                "symbol": "SAMPL"
            }]
        })
    }

    fn instrument() -> Value {
        json!({
            "id": ID,
            "chain_symbol": "SAMPL",
            "type": "call",
            "strike_price": "40.0000",
            "expiration_date": "2026-10-16",
            "trade_value_multiplier": "100.0000"
        })
    }

    fn instruments() -> HashMap<String, Value> {
        HashMap::from([(ID.to_string(), instrument())])
    }

    #[test]
    fn an_exercise_maps_its_contract_shares_and_signed_cash() {
        let e = OptionEvent::from_parts(&exercise(), Some(&instrument())).unwrap();
        assert_eq!(e.event_type.as_deref(), Some("exercise"));
        assert_eq!(e.position_type.as_deref(), Some("long"));
        assert_eq!(e.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(e.option_type.as_deref(), Some("call"));
        assert_eq!(e.strike_price.as_ref().unwrap().amount, "40.00");
        assert_eq!(e.expiration_date.as_deref(), Some("2026-10-16"));
        assert_eq!(e.multiplier.as_deref(), Some("100"));
        assert_eq!(e.quantity.as_deref(), Some("2"));
        assert_eq!(e.cash_amount.as_ref().unwrap().amount, "-8000.00");
        assert_eq!(e.deliveries.len(), 1);
        assert_eq!(e.deliveries[0].side.as_deref(), Some("buy"));
        assert_eq!(e.deliveries[0].quantity.as_deref(), Some("200"));
        assert_eq!(e.deliveries[0].price.as_ref().unwrap().amount, "40.00");
        assert_eq!(e.option_id.as_deref(), Some(ID));
        assert!(e.cash_component.is_none(), "null on the wire stays absent");
    }

    /// An assignment is the writer's side; its credit stays positive.
    #[test]
    fn an_assignment_is_short_and_its_credit_stays_positive() {
        let mut v = exercise();
        v["type"] = json!("assignment");
        v["direction"] = json!("credit");
        v["total_cash_amount"] = json!("7999.94");
        v["equity_components"][0]["side"] = json!("sell");
        let e = OptionEvent::from_parts(&v, Some(&instrument())).unwrap();
        assert_eq!(e.position_type.as_deref(), Some("short"));
        assert_eq!(e.cash_amount.as_ref().unwrap().amount, "7999.94");
    }

    /// An expiration's bare `"0"` must not grow a sign, and the row does not
    /// say which side lapsed.
    #[test]
    fn an_expiration_carries_no_shares_no_side_and_a_zero() {
        let mut v = exercise();
        v["type"] = json!("expiration");
        v["direction"] = json!("credit");
        v["total_cash_amount"] = json!("0");
        v["equity_components"] = json!([]);
        let e = OptionEvent::from_parts(&v, Some(&instrument())).unwrap();
        assert!(e.position_type.is_none());
        assert!(e.deliveries.is_empty());
        assert_eq!(e.cash_amount.as_ref().unwrap().amount, "0.00");

        v["direction"] = json!("debit");
        let e = OptionEvent::from_parts(&v, Some(&instrument())).unwrap();
        assert_eq!(e.cash_amount.as_ref().unwrap().amount, "0.00");
    }

    /// With no instrument, the contract stays unknown — never guessed — and
    /// the delivery's ticker still names the underlying.
    #[test]
    fn an_unresolved_instrument_leaves_the_contract_unknown() {
        let e = OptionEvent::from_parts(&exercise(), None).unwrap();
        assert!(e.strike_price.is_none());
        assert!(e.option_type.is_none());
        assert_eq!(e.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(contract(&e), "?? ?");
    }

    #[test]
    fn the_join_is_by_option_id() {
        let rows = [exercise()];
        let refs: Vec<&Value> = rows.iter().collect();
        let items = join(&refs, &instruments());
        assert_eq!(items[0].strike_price.as_ref().unwrap().amount, "40.00");
        // A row naming only the URL still joins.
        let mut v = exercise();
        v.as_object_mut().unwrap().remove("option_id");
        let refs = vec![&v];
        let items = join(&refs, &instruments());
        assert_eq!(items[0].option_type.as_deref(), Some("call"));
    }

    #[test]
    fn range_and_account_filters_are_client_side_and_keep_undated_rows() {
        let mut other = exercise();
        other["account_number"] = json!("SAMPLE02");
        other["event_date"] = json!("2026-03-01");
        let undated = json!({"id": "x", "account_number": "SAMPLE01"});
        let rows = vec![exercise(), other, undated];
        let range = |s: &str, u: &str| RangeArgs {
            since: Some(s.into()),
            until: Some(u.into()),
            limit: None,
        };
        assert_eq!(
            keep(&rows, &range("2026-10-16", "2026-10-16"), None).len(),
            2
        );
        assert_eq!(
            keep(&rows, &range("2026-01-01", "2026-12-31"), None).len(),
            3
        );
        assert_eq!(
            keep(&rows, &range("2026-01-01", "2026-12-31"), Some("SAMPLE02")).len(),
            1
        );
        let all = RangeArgs {
            since: None,
            until: None,
            limit: None,
        };
        let sorted = keep(&rows, &all, None);
        assert_eq!(
            str_at(sorted[0], "event_date").as_deref(),
            Some("2026-10-16")
        );
    }

    #[test]
    fn the_table_reads_as_option_shorthand() {
        let e = OptionEvent::from_parts(&exercise(), Some(&instrument())).unwrap();
        assert_eq!(contract(&e), "$40.00C 2026-10-16");
        assert_eq!(deliveries_summary(&e), "+200 SAMPL @ $40.00");
    }

    #[test]
    fn the_envelope_is_tagged() {
        let page = Paged::new(
            "option-event",
            vec![OptionEvent::from_parts(&exercise(), Some(&instrument())).unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "option-event-list/v1");
        assert_eq!(v["items"][0]["event_type"], "exercise");
        assert_eq!(v["items"][0]["deliveries"][0]["side"], "buy");
    }
}
