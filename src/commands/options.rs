//! `rhd options positions` — open option positions, valued at the mark.
//!
//! Three reads, all LIVE-VERIFIED 2026-10-01 (docs/api.md §3.9):
//!
//! 1. `GET /options/positions/?nonzero=true` — one row per held contract.
//!    Carries the underlying (`chain_symbol`), `type` (**long/short**, not
//!    call/put), quantity, a per-*contract* `average_price`, and the
//!    clearing firm's remaining-lot basis (`clearing_cost_basis` +
//!    `clearing_direction`). **No strike and no call/put.**
//! 2. `GET /options/instruments/?ids=` — batched; strike, expiry, and the
//!    call/put `type`. Rows come back in a different order than asked, so
//!    the join is by `id`, never by position.
//! 3. `GET /marketdata/options/?ids=` — batched; `mark_price` per *share*.
//!
//! The trap that shapes the DTO: `average_price × quantity` and
//! `clearing_cost_basis` **disagree** once a position has been partly
//! closed. Live, the clearing figure matched FIFO remaining-lot basis to the
//! cent and the average figure matched a running average-cost basis. Tax
//! lots are FIFO by default, so `cost_basis` is the clearing figure and
//! `average_open_price` stays what the app displays.

use std::collections::{BTreeSet, HashMap};

use pk_cli_core::{output, CliError, Money, Paged};
use serde::Serialize;
use serde_json::Value;

use crate::commands::option_instruments::{fetch_by_ids, option_id_of, INSTRUMENTS_PATH};
use crate::commands::{date_of, fanout, money_at, str_at, trim_quantity, Ctx};
use crate::fixed::{div_fixed, from_fixed, mul_fixed, to_fixed};

pub const POSITIONS_PATH: &str = "/options/positions/";
pub const MARKETDATA_PATH: &str = "/marketdata/options/";

/// One open option position (`option-position/v1`).
///
/// **Sign convention** (ours, not the wire's): `cost_basis` and
/// `market_value` are signed by position — positive for a long (premium
/// paid, an asset), negative for a short (premium received, a liability to
/// close) — so `unrealized_pl = market_value − cost_basis` holds for both.
#[derive(Debug, Serialize)]
pub struct OptionPosition {
    /// The underlying's ticker (`chain_symbol`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// `call` | `put` — from the option instrument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strike_price: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,
    /// `long` | `short` — the wire's position-level `type`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position_type: Option<String>,
    /// Contracts held, unsigned (`position_type` carries the direction).
    pub quantity: String,
    /// Shares per contract (`trade_value_multiplier`, `100` for a standard
    /// contract; adjusted contracts differ).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplier: Option<String>,
    /// Average open price **per share** — the wire's per-contract
    /// `average_price` ÷ the multiplier. A running average; see
    /// `cost_basis` for the tax-lot figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_open_price: Option<Money>,
    /// Basis of the lots still open, signed by position (see the type doc).
    /// The clearing firm's FIFO remaining-lot figure
    /// (`clearing_cost_basis`); falls back to average × quantity ×
    /// multiplier only when the wire omits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_basis: Option<Money>,
    /// Mark price **per share** (`mark_price`, falling back to
    /// `adjusted_mark_price`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark_price: Option<Money>,
    /// mark × quantity × multiplier, signed by position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_value: Option<Money>,
    /// `market_value − cost_basis`. Omitted when either side is unknown —
    /// never computed against a guessed zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unrealized_pl: Option<Money>,
    /// When the mark was struck (the marketdata row's `updated_at`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark_as_of: Option<String>,
    /// The OCC contract symbol (`SAMPL 261030C00050000` shape) — the
    /// identity a wash-sale check keys "the same contract" on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occ_symbol: Option<String>,
    /// Date the position was opened (`opened_at`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    /// Tagged by `--all-accounts` (docs/api.md §3.14).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_kind: Option<String>,
    /// `true` on a row from the login's default account under
    /// `--all-accounts`; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_default: Option<bool>,
    /// The option instrument's UUID — the join key to `transactions
    /// options` legs and `rhd api GET /options/instruments/<id>/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub option_id: Option<String>,
}

/// +1 for a long, −1 for a short, `None` for anything else — an unknown
/// direction leaves every signed figure unset rather than guessing.
fn position_sign(pos: &Value) -> Option<i64> {
    match str_at(pos, "type").as_deref() {
        Some("long") => Some(1),
        Some("short") => Some(-1),
        _ => None,
    }
}

/// A wire amount as unsigned fixed point. Robinhood signs some figures and
/// not others (and community reports disagree on whether a short's
/// `average_price` arrives negative), so magnitudes are taken here and the
/// sign is applied from the position's own direction fields.
fn magnitude(v: &Value, key: &str) -> Option<i64> {
    money_at(v, key)
        .and_then(|m| to_fixed(&m.amount))
        .map(i64::abs)
}

/// The per-share mark a marketdata row offers, in fixed point.
fn mark_of(md: &Value) -> Option<i64> {
    money_at(md, "mark_price")
        .or_else(|| money_at(md, "adjusted_mark_price"))
        .and_then(|m| to_fixed(&m.amount))
}

impl OptionPosition {
    /// Join one position row with its instrument and marketdata rows.
    /// `None` for a row with no readable or a zero quantity (a closed lot
    /// that slipped past `nonzero=true` is not an open position).
    pub fn from_parts(pos: &Value, inst: Option<&Value>, md: Option<&Value>) -> Option<Self> {
        let raw_qty = str_at(pos, "quantity")?;
        let qty = to_fixed(&raw_qty)?.abs();
        if qty == 0 {
            return None;
        }
        let sign = position_sign(pos);
        let multiplier = str_at(pos, "trade_value_multiplier")
            .or_else(|| inst.and_then(|i| str_at(i, "trade_value_multiplier")));
        let mult = multiplier.as_deref().and_then(to_fixed).filter(|m| *m > 0);

        let avg_contract = magnitude(pos, "average_price");
        let average_open_price = avg_contract
            .zip(mult)
            .and_then(|(a, m)| div_fixed(a, m))
            .map(|v| from_fixed(v.into()));

        let cost_basis = cost_basis(pos, sign, qty, avg_contract);

        let mark = md.and_then(mark_of);
        let market_value = (|| {
            let per_contract = mul_fixed(mark?, mult?)?;
            Some(mul_fixed(per_contract, qty)? * sign?)
        })();
        let unrealized_pl = market_value
            .zip(cost_basis)
            .and_then(|(mv, cb)| mv.checked_sub(cb));

        Some(OptionPosition {
            symbol: str_at(pos, "chain_symbol").or_else(|| md.and_then(|m| str_at(m, "symbol"))),
            option_type: inst.and_then(|i| str_at(i, "type")),
            strike_price: inst.and_then(|i| money_at(i, "strike_price")),
            expiration_date: str_at(pos, "expiration_date")
                .or_else(|| inst.and_then(|i| str_at(i, "expiration_date"))),
            position_type: str_at(pos, "type"),
            quantity: trim_quantity(&raw_qty),
            multiplier: multiplier.map(|m| trim_quantity(&m)),
            average_open_price,
            cost_basis: cost_basis.map(|v| from_fixed(v.into())),
            mark_price: mark.map(|v| from_fixed(v.into())),
            market_value: market_value.map(|v| from_fixed(v.into())),
            unrealized_pl: unrealized_pl.map(|v| from_fixed(v.into())),
            mark_as_of: md.and_then(|m| str_at(m, "updated_at")),
            occ_symbol: md.and_then(|m| str_at(m, "occ_symbol")),
            opened_at: date_of(pos, "opened_at"),
            account_number: fanout::row_account(pos),
            account_kind: fanout::kind_of(pos),
            account_default: fanout::default_of(pos),
            option_id: option_id_of(pos),
        })
    }
}

/// Signed basis of the open lots, in fixed point.
///
/// `clearing_cost_basis` is the primary: it is the FIFO remaining-lot
/// figure (live-verified against the order history, docs/api.md §3.9),
/// signed by `clearing_direction` (`debit` = paid = long-side positive,
/// `credit` = received = negative). Only when it is absent does the running
/// average stand in — `average_price` is already per contract, so it is ×
/// quantity, signed by the position's own direction.
fn cost_basis(pos: &Value, sign: Option<i64>, qty: i64, avg_contract: Option<i64>) -> Option<i64> {
    if let Some(clearing) = magnitude(pos, "clearing_cost_basis") {
        let dir = match str_at(pos, "clearing_direction").as_deref() {
            Some("debit") => Some(1),
            Some("credit") => Some(-1),
            _ => sign,
        };
        return dir.map(|d| clearing * d);
    }
    Some(mul_fixed(avg_contract?, qty)? * sign?)
}

/// Keep the rows for the selected account, when one is selected. Every live
/// row names its own `account_number`; a row that doesn't cannot be
/// attributed, so under a filter it is dropped rather than assumed.
fn scope<'a>(rows: &'a [Value], account: Option<&str>) -> Vec<&'a Value> {
    rows.iter()
        .filter(|r| match account {
            Some(a) => str_at(r, "account_number").as_deref() == Some(a),
            None => true,
        })
        .collect()
}

/// Join positions to instruments and marks. Pure, so the whole mapping is
/// pinned offline against the fixtures.
pub fn join(
    rows: &[&Value],
    instruments: &HashMap<String, Value>,
    marks: &HashMap<String, Value>,
) -> Vec<OptionPosition> {
    rows.iter()
        .filter_map(|pos| {
            let id = option_id_of(pos);
            let inst = id.as_ref().and_then(|i| instruments.get(i));
            let md = id.as_ref().and_then(|i| marks.get(i));
            OptionPosition::from_parts(pos, inst, md)
        })
        .collect()
}

pub fn positions(ctx: &Ctx, all_accounts: bool) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    // `nonzero=true` keeps closed contracts out, as on equity positions.
    // Without --all-accounts, account scoping is client-side: every row
    // names its own account. Under it, each open account is read with the
    // `account_numbers` parameter the provider's web app sends, every row
    // verified against it (docs/api.md §3.14).
    let (rows, account) = if all_accounts {
        let rows = fanout::read_all(ctx, &token, true, "option position", |s| {
            ctx.rh.paginate(
                &token,
                POSITIONS_PATH,
                &[
                    ("nonzero", "true".to_string()),
                    ("account_numbers", s.number.clone()),
                ],
                None,
            )
        })?;
        (rows, None)
    } else {
        let rows = ctx.rh.paginate(
            &token,
            POSITIONS_PATH,
            &[("nonzero", "true".to_string())],
            None,
        )?;
        (rows, ctx.account.as_deref())
    };
    let kept = scope(&rows, account);

    let ids: BTreeSet<String> = kept.iter().filter_map(|r| option_id_of(r)).collect();
    let (instruments, marks) = if ids.is_empty() {
        (HashMap::new(), HashMap::new())
    } else {
        (
            fetch_by_ids(ctx, &token, INSTRUMENTS_PATH, &ids, "id")?,
            fetch_by_ids(ctx, &token, MARKETDATA_PATH, &ids, "instrument_id")?,
        )
    };

    let items = join(&kept, &instruments, &marks);
    if !ctx.common.quiet {
        warn_gaps(&items);
    }

    let page = Paged::new("option-position", items);
    if ctx.common.json {
        page.emit(true);
    } else {
        output::table(&table_rows(&page.items));
    }
    Ok(())
}

/// Say on stderr when a contract could not be fully described or valued —
/// the DTO omits the field, and a silent blank would read as "fine".
fn warn_gaps(items: &[OptionPosition]) {
    let unpriced = items.iter().filter(|p| p.unrealized_pl.is_none()).count();
    let undescribed = items
        .iter()
        .filter(|p| p.strike_price.is_none() || p.option_type.is_none())
        .count();
    if unpriced > 0 {
        eprintln!(
            "{unpriced} position(s) could not be valued (no mark, multiplier, or basis) — \
             market value and unrealized P/L omitted for them"
        );
    }
    if undescribed > 0 {
        eprintln!("{undescribed} position(s) missing strike or call/put detail");
    }
}

/// The text table: one contract per row, described in option shorthand
/// (`$8.00C 2026-11-20`), `?` where a piece is missing.
fn table_rows(items: &[OptionPosition]) -> Vec<Value> {
    let m = |v: &Option<Money>| {
        v.as_ref()
            .map(|m| Value::String(format!("${}", m.amount)))
            .unwrap_or(Value::Null)
    };
    items
        .iter()
        .map(|p| {
            let strike = p
                .strike_price
                .as_ref()
                .map(|s| format!("${}", s.amount))
                .unwrap_or_else(|| "?".into());
            let t = match p.option_type.as_deref() {
                Some("call") => "C",
                Some("put") => "P",
                Some(other) => other,
                None => "?",
            };
            let exp = p.expiration_date.as_deref().unwrap_or("?");
            serde_json::json!({
                "symbol": p.symbol.as_deref().unwrap_or("?"),
                "contract": format!("{strike}{t} {exp}"),
                "position": p.position_type.as_deref().unwrap_or("?"),
                "qty": p.quantity,
                "avg_open": m(&p.average_open_price),
                "mark": m(&p.mark_price),
                "cost_basis": m(&p.cost_basis),
                "market_value": m(&p.market_value),
                "unrealized_pl": m(&p.unrealized_pl),
                "account": p.account_number.as_deref().unwrap_or(""),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::option_instruments::index_by;
    use serde_json::json;

    const ID: &str = "00000000-0000-4000-8000-0000000000b1";

    fn long_row() -> Value {
        json!({
            "account_number": "SAMPLE01",
            "average_price": "150.0000",
            "chain_symbol": "SAMPL",
            "option": format!("https://api.robinhood.com/options/instruments/{ID}/"),
            "option_id": ID,
            "type": "long",
            "quantity": "4.0000",
            "trade_value_multiplier": "100.0000",
            "expiration_date": "2026-10-30",
            "clearing_cost_basis": "600.0000",
            "clearing_direction": "debit",
            "opened_at": "2026-09-01T15:00:00.000000Z"
        })
    }

    fn inst() -> Value {
        json!({"id": ID, "type": "call", "strike_price": "50.0000", "expiration_date": "2026-10-30"})
    }

    fn md(mark: &str) -> Value {
        json!({
            "instrument_id": ID,
            "mark_price": mark,
            "adjusted_mark_price": "9.990000",
            "occ_symbol": "SAMPL 261030C00050000",
            "updated_at": "2026-10-01T18:00:00Z"
        })
    }

    #[test]
    fn a_long_call_is_valued_at_the_mark() {
        let p =
            OptionPosition::from_parts(&long_row(), Some(&inst()), Some(&md("1.250000"))).unwrap();
        assert_eq!(p.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(p.option_type.as_deref(), Some("call"));
        assert_eq!(p.strike_price.as_ref().unwrap().amount, "50.00");
        assert_eq!(p.quantity, "4");
        assert_eq!(p.multiplier.as_deref(), Some("100"));
        // 150.00 per contract / 100 = 1.50 per share.
        assert_eq!(p.average_open_price.unwrap().amount, "1.50");
        assert_eq!(p.cost_basis.unwrap().amount, "600.00");
        assert_eq!(p.mark_price.unwrap().amount, "1.25");
        // 1.25 × 100 × 4 = 500; 500 − 600 = −100.
        assert_eq!(p.market_value.unwrap().amount, "500.00");
        assert_eq!(p.unrealized_pl.unwrap().amount, "-100.00");
        assert_eq!(p.occ_symbol.as_deref(), Some("SAMPL 261030C00050000"));
        assert_eq!(p.opened_at.as_deref(), Some("2026-09-01"));
    }

    /// The live trap: after a partial close the clearing (FIFO) basis and
    /// average × quantity disagree. The tax-lot figure wins.
    #[test]
    fn clearing_basis_wins_over_the_running_average() {
        let mut row = long_row();
        row["average_price"] = json!("175.0000"); // 175 × 4 = 700 ≠ 600
        let p = OptionPosition::from_parts(&row, Some(&inst()), Some(&md("1.250000"))).unwrap();
        assert_eq!(p.cost_basis.unwrap().amount, "600.00");
        assert_eq!(p.average_open_price.unwrap().amount, "1.75");
    }

    #[test]
    fn without_a_clearing_figure_the_average_stands_in() {
        let mut row = long_row();
        row.as_object_mut().unwrap().remove("clearing_cost_basis");
        let p = OptionPosition::from_parts(&row, Some(&inst()), Some(&md("2.000000"))).unwrap();
        assert_eq!(p.cost_basis.unwrap().amount, "600.00");
        assert_eq!(p.unrealized_pl.unwrap().amount, "200.00");
    }

    /// A short is a liability: basis (premium received) and market value
    /// (cost to close) are both negative, so P/L = mv − basis still reads
    /// right — a falling mark is a gain.
    #[test]
    fn a_short_is_signed_as_a_liability() {
        let mut row = long_row();
        row["type"] = json!("short");
        row["clearing_direction"] = json!("credit");
        // Whether a short's average arrives negative is unsettled in the
        // community record; the magnitude is taken either way.
        row["average_price"] = json!("-150.0000");
        let p = OptionPosition::from_parts(&row, Some(&inst()), Some(&md("1.000000"))).unwrap();
        assert_eq!(p.average_open_price.unwrap().amount, "1.50");
        assert_eq!(p.cost_basis.unwrap().amount, "-600.00");
        assert_eq!(p.market_value.unwrap().amount, "-400.00");
        assert_eq!(p.unrealized_pl.unwrap().amount, "200.00");
    }

    #[test]
    fn the_adjusted_mark_stands_in_for_a_missing_mark() {
        let mut m = md("1.000000");
        m.as_object_mut().unwrap().remove("mark_price");
        let p = OptionPosition::from_parts(&long_row(), Some(&inst()), Some(&m)).unwrap();
        assert_eq!(p.mark_price.unwrap().amount, "9.99");
    }

    /// No mark means no market value and no P/L — never a $0 valuation.
    #[test]
    fn an_unpriced_contract_omits_value_rather_than_zeroing_it() {
        let p = OptionPosition::from_parts(&long_row(), Some(&inst()), None).unwrap();
        assert!(p.mark_price.is_none());
        assert!(p.market_value.is_none());
        assert!(p.unrealized_pl.is_none());
        assert_eq!(p.cost_basis.unwrap().amount, "600.00");
        let v = serde_json::to_value(OptionPosition::from_parts(&long_row(), None, None).unwrap())
            .unwrap();
        assert!(v.get("market_value").is_none());
        assert!(v.get("strike_price").is_none());
    }

    #[test]
    fn an_unknown_direction_leaves_signed_figures_unset() {
        let mut row = long_row();
        row["type"] = json!("mystery");
        row.as_object_mut().unwrap().remove("clearing_direction");
        let p = OptionPosition::from_parts(&row, Some(&inst()), Some(&md("1.000000"))).unwrap();
        assert!(p.cost_basis.is_none());
        assert!(p.market_value.is_none());
        assert!(p.unrealized_pl.is_none());
    }

    #[test]
    fn a_zero_or_unreadable_quantity_is_not_an_open_position() {
        let mut row = long_row();
        row["quantity"] = json!("0.0000");
        assert!(OptionPosition::from_parts(&row, None, None).is_none());
        row["quantity"] = json!("n/a");
        assert!(OptionPosition::from_parts(&row, None, None).is_none());
    }

    #[test]
    fn the_option_id_falls_back_to_the_url() {
        let mut row = long_row();
        row.as_object_mut().unwrap().remove("option_id");
        assert_eq!(option_id_of(&row).as_deref(), Some(ID));
    }

    #[test]
    fn an_account_filter_keeps_only_attributable_rows() {
        let mut other = long_row();
        other["account_number"] = json!("SAMPLE02");
        let mut anon = long_row();
        anon.as_object_mut().unwrap().remove("account_number");
        let rows = vec![long_row(), other, anon];
        assert_eq!(scope(&rows, None).len(), 3);
        let kept = scope(&rows, Some("SAMPLE01"));
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn null_marketdata_entries_are_skipped_and_urls_join() {
        let rows = vec![
            Value::Null,
            json!({"instrument": format!("https://api.robinhood.com/options/instruments/{ID}/"),
                   "mark_price": "1.000000"}),
        ];
        let idx = index_by(&rows, "instrument_id");
        assert!(idx.contains_key(ID));
    }

    #[test]
    fn the_table_describes_the_contract_in_shorthand() {
        let p =
            OptionPosition::from_parts(&long_row(), Some(&inst()), Some(&md("1.250000"))).unwrap();
        let rows = table_rows(&[p]);
        assert_eq!(rows[0]["contract"], "$50.00C 2026-10-30");
        assert_eq!(rows[0]["unrealized_pl"], "$-100.00");
        let bare = OptionPosition::from_parts(&long_row(), None, None).unwrap();
        assert_eq!(table_rows(&[bare])[0]["contract"], "?? 2026-10-30");
    }

    fn fixture_rows(name: &str) -> Vec<Value> {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["results"].as_array().unwrap().clone()
    }

    /// The whole three-read pipeline over the fixtures, exactly as the wire
    /// shapes arrive — instruments out of request order included.
    #[test]
    fn the_fixtures_join_into_valued_positions() {
        let positions = fixture_rows("options_positions.json");
        let instruments = index_by(&fixture_rows("options_instruments.json"), "id");
        let marks = index_by(&fixture_rows("options_marketdata.json"), "instrument_id");
        let rows: Vec<&Value> = positions.iter().collect();
        let out = join(&rows, &instruments, &marks);
        assert_eq!(out.len(), 3);

        let first = &out[0];
        assert_eq!(first.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(first.option_type.as_deref(), Some("call"));
        assert_eq!(first.strike_price.as_ref().unwrap().amount, "50.00");
        assert_eq!(first.expiration_date.as_deref(), Some("2026-10-30"));
        // The partly-closed trap: avg 175/contract, FIFO basis 600 (not 700).
        assert_eq!(first.average_open_price.as_ref().unwrap().amount, "1.75");
        assert_eq!(first.cost_basis.as_ref().unwrap().amount, "600.00");
        assert_eq!(first.market_value.as_ref().unwrap().amount, "500.00");
        assert_eq!(first.unrealized_pl.as_ref().unwrap().amount, "-100.00");

        let put = &out[1];
        assert_eq!(put.option_type.as_deref(), Some("put"));
        assert_eq!(put.occ_symbol.as_deref(), Some("TESTF 261120P00025000"));
        // 0.75 × 100 × 2 = 150 against 100 basis.
        assert_eq!(put.unrealized_pl.as_ref().unwrap().amount, "50.00");

        // Sub-cent marks survive: 0.105 × 100 × 10 = 105.
        assert_eq!(out[2].mark_price.as_ref().unwrap().amount, "0.105");
        assert_eq!(out[2].market_value.as_ref().unwrap().amount, "105.00");
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new(
            "option-position",
            vec![OptionPosition::from_parts(&long_row(), None, None).unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "option-position-list/v1");
    }
}
