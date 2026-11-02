//! `rhd interest list` — cash-sweep interest payments in a date range.
//!
//! This is the 1099-INT reconciliation surface. Robinhood pays brokerage cash
//! interest through its sweep program, and those payments live at
//! `/accounts/sweeps/` — not with dividends, and not in the order history.
//!
//! # LIVE-VERIFIED 2026-08-13
//!
//! Captured against a real account (docs/api.md §3.7). Shape facts:
//!
//! - money is a **nested object** (`{"amount", "currency_code", …}`), unlike
//!   the flat strings most fields use (dividends' DRIP execution price nests
//!   the same shape) — read with `money_obj_at`;
//! - `account_number` is direct (no URL to chase);
//! - every observed row is `direction: "credit"`, `reason:
//!   "interest_payment"`; `payout_type` varies and passes through verbatim.

use pk_cli_core::{CliError, Paged, RangeArgs};
use serde::Serialize;
use serde_json::Value;

use crate::commands::{money_obj_at, str_at, Ctx};

pub const PATH: &str = "/accounts/sweeps/";

/// One interest payment (`interest/v1`).
#[derive(Debug, Serialize)]
pub struct Interest {
    pub id: String,
    /// The `pay_date` — already a bare ISO date on the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<pk_cli_core::Money>,
    /// Provider's own word (`end_of_month_payment`, `program_opt_out`, …) —
    /// a new payout type must stay visible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payout_type: Option<String>,
    /// `credit` on every observed row; surfaced so a debit could never hide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
}

impl Interest {
    pub(crate) fn from_json(v: &Value) -> Option<Self> {
        let id = str_at(v, "id")?;
        Some(Interest {
            id,
            date: str_at(v, "pay_date"),
            amount: money_obj_at(v, "amount"),
            payout_type: str_at(v, "payout_type"),
            direction: str_at(v, "direction"),
            account_number: str_at(v, "account_number"),
        })
    }
}

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    // No server-side date or account parameter is known for sweeps; both
    // bounds are applied client-side.
    let rows = ctx.rh.paginate(&token, PATH, &[], None)?;

    let mut items: Vec<Interest> = rows
        .iter()
        .filter(|r| within(r, range.since.as_deref(), range.until.as_deref()))
        .filter(|r| match &ctx.account {
            Some(acct) => str_at(r, "account_number").as_deref() == Some(acct.as_str()),
            None => true,
        })
        .filter_map(Interest::from_json)
        .collect();
    // Newest first, like the other date-bearing lists.
    items.sort_by(|a, b| b.date.cmp(&a.date));
    if let Some(n) = range.limit {
        items.truncate(n as usize);
    }

    Paged::new("interest", items).emit(ctx.common.json);
    Ok(())
}

pub(crate) fn within(row: &Value, since: Option<&str>, until: Option<&str>) -> bool {
    match str_at(row, "pay_date") {
        Some(d) => crate::commands::date_within(&d, since, until),
        // Undated rows are kept rather than silently dropped.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "id": "00000000-0000-4000-8000-000000000040",
            "account_number": "SAMPLE01",
            "amount": {"amount": "1.2300", "currency_code": "USD", "currency_id": "00000000-0000-4000-8000-000000000099"},
            "direction": "credit",
            "pay_date": "2026-06-30",
            "pay_period_start": "2026-06-01",
            "pay_period_end": "2026-06-30",
            "payout_type": "end_of_month_payment",
            "reason": "interest_payment"
        })
    }

    #[test]
    fn a_sweep_row_maps_with_its_nested_money() {
        let i = Interest::from_json(&sample()).unwrap();
        assert_eq!(i.date.as_deref(), Some("2026-06-30"));
        assert_eq!(i.payout_type.as_deref(), Some("end_of_month_payment"));
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["amount"]["amount"], "1.23");
        assert_eq!(v["amount"]["currency"], "USD");
    }

    #[test]
    fn range_filtering_is_inclusive_and_keeps_undated_rows() {
        let row = sample();
        assert!(within(&row, Some("2026-06-30"), Some("2026-06-30")));
        assert!(!within(&row, Some("2026-07-01"), None));
        assert!(!within(&row, None, Some("2026-06-29")));
        assert!(within(&json!({"id": "x"}), Some("2026-01-01"), None));
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new("interest", vec![Interest::from_json(&sample()).unwrap()]);
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "interest-list/v1");
        assert_eq!(v["items"][0]["direction"], "credit");
    }
}
