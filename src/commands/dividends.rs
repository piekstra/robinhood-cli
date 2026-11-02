//! `rhd dividends list` — dividend payments in a date range.
//!
//! This is the 1099-DIV reconciliation surface: what Robinhood paid (or
//! reinvested) during the year, so a year-end estimate can be trued up before
//! the consolidated 1099 lands. As with orders, the 1099 itself stays the
//! source of truth for filed figures.
//!
//! # LIVE-VERIFIED 2026-08-13
//!
//! Captured against a real account (docs/api.md §3.6). The shape facts the
//! code leans on:
//!
//! - a dividend carries no symbol, only an `instrument` URL — resolved with
//!   the same batched lookup positions use;
//! - `paid_at` is null exactly for `voided` dividends (fall back to
//!   `payable_date` so voided rows still sort and filter);
//! - `account_number_rhs` is a **direct** account number, unlike the
//!   `account` URL next to it;
//! - `reinvested` rows carry extra DRIP keys that other rows lack entirely —
//!   absent, not null — so nothing here may require them.

use std::collections::HashMap;

use pk_cli_core::{CliError, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use crate::commands::{date_of, money_at, str_at, Ctx};

pub const PATH: &str = "/dividends/";

/// One dividend payment (`dividend/v1`).
#[derive(Debug, Serialize)]
pub struct Dividend {
    pub id: String,
    /// Payment date (`paid_at`), falling back to `payable_date` for rows —
    /// observed live: exactly the `voided` ones — that were never paid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Net amount credited (or reinvested). The provider's `amount` is net of
    /// `withholding`; both are surfaced so DIV box math is checkable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<pk_cli_core::Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withholding: Option<pk_cli_core::Money>,
    /// `paid` | `reinvested` | `voided` observed live; anything new passes
    /// through verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
}

impl Dividend {
    pub(crate) fn from_json(v: &Value, symbols: &HashMap<String, String>) -> Option<Self> {
        let id = str_at(v, "id")?;
        Some(Dividend {
            id,
            date: dividend_date(v),
            symbol: str_at(v, "instrument")
                .as_deref()
                .and_then(|u| symbols.get(u))
                .cloned(),
            amount: money_at(v, "amount"),
            withholding: money_at(v, "withholding"),
            state: str_at(v, "state"),
            account_number: str_at(v, "account_number_rhs"),
        })
    }
}

/// `paid_at` when the dividend was actually paid; `payable_date` otherwise.
fn dividend_date(v: &Value) -> Option<String> {
    date_of(v, "paid_at").or_else(|| date_of(v, "payable_date"))
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    // No server-side date or account parameter is known for /dividends/, so
    // both bounds are applied here after the (single, observed) page loads.
    let rows = ctx.rh.paginate(&token, PATH, &[], None)?;

    let mut kept: Vec<&Value> = rows
        .iter()
        .filter(|r| within(r, range.since.as_deref(), range.until.as_deref()))
        .filter(|r| match &ctx.account {
            Some(acct) => str_at(r, "account_number_rhs").as_deref() == Some(acct.as_str()),
            None => true,
        })
        .collect();
    // Newest first, like the other date-bearing lists, so `--limit N` means
    // "the N most recent" rather than whatever order the endpoint returned.
    kept.sort_by_key(|r| std::cmp::Reverse(dividend_date(r)));
    if let Some(n) = range.limit {
        kept.truncate(n as usize);
    }

    let symbols = crate::commands::instruments::resolve_symbols(ctx, &token, &kept)?;
    let items: Vec<Dividend> = kept
        .iter()
        .filter_map(|r| Dividend::from_json(r, &symbols))
        .collect();

    Paged::new("dividend", items).emit(ctx.common.json);
    Ok(())
}

/// Whether a dividend's payment date falls inside the requested range.
pub(crate) fn within(row: &Value, since: Option<&str>, until: Option<&str>) -> bool {
    match dividend_date(row) {
        Some(d) => crate::commands::date_within(&d, since, until),
        // Undated rows are kept rather than silently dropped — losing a
        // payment silently is the worse failure for tax work.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn paid() -> Value {
        json!({
            "id": "00000000-0000-4000-8000-000000000030",
            "account": "https://api.robinhood.com/accounts/SAMPLE01/",
            "account_number_rhs": "SAMPLE01",
            "instrument": "https://api.robinhood.com/instruments/00000000-0000-4000-8000-000000000001/",
            "amount": "12.3400",
            "gross_amount": "12.3400",
            "withholding": "0.00",
            "record_date": "2026-03-10",
            "payable_date": "2026-03-14",
            "paid_at": "2026-03-14T16:00:00Z",
            "state": "paid"
        })
    }

    #[test]
    fn a_paid_dividend_maps_with_its_payment_date() {
        let mut symbols = HashMap::new();
        symbols.insert(
            "https://api.robinhood.com/instruments/00000000-0000-4000-8000-000000000001/"
                .to_string(),
            "SAMPL".to_string(),
        );
        let d = Dividend::from_json(&paid(), &symbols).unwrap();
        assert_eq!(d.date.as_deref(), Some("2026-03-14"));
        assert_eq!(d.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(d.state.as_deref(), Some("paid"));
        assert_eq!(d.account_number.as_deref(), Some("SAMPLE01"));
    }

    /// Observed live: `paid_at` is null exactly for voided dividends. The row
    /// must still date itself (via `payable_date`) so filtering keeps working.
    #[test]
    fn a_voided_dividend_falls_back_to_the_payable_date() {
        let mut v = paid();
        v["paid_at"] = json!(null);
        v["state"] = json!("voided");
        let d = Dividend::from_json(&v, &HashMap::new()).unwrap();
        assert_eq!(d.date.as_deref(), Some("2026-03-14"));
    }

    /// Reinvested rows carry DRIP keys other rows lack entirely; nothing in
    /// the mapping may require them.
    #[test]
    fn a_reinvested_dividend_needs_no_drip_fields() {
        let mut v = paid();
        v["state"] = json!("reinvested");
        // No drip_* keys at all — the common case for the *other* states.
        let d = Dividend::from_json(&v, &HashMap::new()).unwrap();
        assert_eq!(d.state.as_deref(), Some("reinvested"));
    }

    #[test]
    fn range_filtering_is_inclusive_and_keeps_undated_rows() {
        let row = paid();
        assert!(within(&row, Some("2026-03-14"), Some("2026-03-14")));
        assert!(!within(&row, Some("2026-03-15"), None));
        assert!(!within(&row, None, Some("2026-03-13")));
        assert!(within(&json!({"id": "x"}), Some("2026-01-01"), None));
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new(
            "dividend",
            vec![Dividend::from_json(&paid(), &HashMap::new()).unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "dividend-list/v1");
        assert_eq!(v["items"][0]["amount"]["amount"], "12.34");
    }
}
