//! `rhd positions list` — current holdings.
//!
//! A position carries no symbol, only an `instrument` URL, so symbols are
//! resolved separately. That resolution is **batched** (`/instruments/?ids=`)
//! rather than one request per row: a 40-holding account would otherwise cost
//! 40 extra round trips against a rate-limited API.

use std::collections::HashMap;

use pk_cli_core::{CliError, Paged};
use serde::Serialize;
use serde_json::Value;

use crate::commands::{fanout, money_at, str_at, Ctx};

pub const PATH: &str = "/positions/";

/// One holding (`position/v1`).
#[derive(Debug, Serialize)]
pub struct Position {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub quantity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_buy_price: Option<pk_cli_core::Money>,
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
    /// Kept so a caller can resolve the instrument itself if it wants more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument: Option<String>,
}

impl Position {
    fn from_json(v: &Value, symbols: &HashMap<String, String>) -> Option<Self> {
        let quantity = str_at(v, "quantity")?;
        let instrument = str_at(v, "instrument");
        let symbol = instrument
            .as_deref()
            .and_then(|url| symbols.get(url))
            .cloned();
        Some(Position {
            symbol,
            quantity: crate::commands::trim_quantity(&quantity),
            average_buy_price: money_at(v, "average_buy_price"),
            account_number: fanout::row_account(v),
            account_kind: fanout::kind_of(v),
            account_default: fanout::default_of(v),
            instrument,
        })
    }
}

/// The positions query for one read: current holdings unless `all`, scoped
/// to `account` when one is named.
fn query(all: bool, account: Option<&str>) -> Vec<(&'static str, String)> {
    let mut query: Vec<(&'static str, String)> = Vec::new();
    if !all {
        // Without this the endpoint returns every position ever held, so a
        // long-lived account's "holdings" would be mostly closed lots.
        query.push(("nonzero", "true".to_string()));
    }
    if let Some(acct) = account {
        query.push(("account_number", acct.to_string()));
    }
    query
}

pub fn list(ctx: &Ctx, limit: Option<u32>, all: bool, all_accounts: bool) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    let rows = if all_accounts {
        // Holdings live in open accounts — unless `--all` asks for closed
        // positions too, which a closed account can still list.
        let mut rows = fanout::read_all(ctx, &token, !all, "position", |s| {
            ctx.rh
                .paginate(&token, PATH, &query(all, Some(&s.number)), None)
        })?;
        if let Some(n) = limit {
            rows.truncate(n as usize);
        }
        rows
    } else {
        ctx.rh
            .paginate(&token, PATH, &query(all, ctx.account.as_deref()), limit)?
    };
    let refs: Vec<&Value> = rows.iter().collect();
    let symbols = crate::commands::instruments::resolve_symbols(ctx, &token, &refs)?;

    let positions: Vec<Position> = rows
        .iter()
        .filter_map(|r| Position::from_json(r, &symbols))
        .collect();
    Paged::new("position", positions).emit(ctx.common.json);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::instrument_id;
    use serde_json::json;

    fn sample() -> Value {
        json!({
            "url": "https://api.robinhood.com/positions/8UD09348/abcd/",
            "instrument": "https://api.robinhood.com/instruments/00000000-0000-4000-8000-000000000001/",
            "account_number": "8UD09348",
            "quantity": "10.00000000",
            "average_buy_price": "150.0000",
            "shares_held_for_sells": "0.00000000"
        })
    }

    #[test]
    fn instrument_ids_come_out_of_the_url() {
        assert_eq!(
            instrument_id("https://api.robinhood.com/instruments/abc-123/").as_deref(),
            Some("abc-123")
        );
        // No trailing slash is equally valid.
        assert_eq!(
            instrument_id("https://api.robinhood.com/instruments/abc-123").as_deref(),
            Some("abc-123")
        );
        assert_eq!(instrument_id(""), None);
    }

    #[test]
    fn a_resolved_symbol_lands_on_the_row() {
        let mut symbols = HashMap::new();
        symbols.insert(
            "https://api.robinhood.com/instruments/00000000-0000-4000-8000-000000000001/"
                .to_string(),
            "SAMPL".to_string(),
        );
        let p = Position::from_json(&sample(), &symbols).unwrap();
        assert_eq!(p.symbol.as_deref(), Some("SAMPL"));
        assert_eq!(p.quantity, "10");
        assert_eq!(p.account_number.as_deref(), Some("8UD09348"));
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["average_buy_price"]["amount"], "150.00");
    }

    /// An unresolved instrument must not invent a symbol — the row is still
    /// useful (quantity, cost basis), and a wrong ticker would be worse.
    #[test]
    fn an_unresolved_instrument_omits_the_symbol() {
        let p = Position::from_json(&sample(), &HashMap::new()).unwrap();
        assert!(p.symbol.is_none());
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("symbol").is_none());
    }

    #[test]
    fn a_row_without_a_quantity_is_dropped() {
        assert!(Position::from_json(&json!({"instrument": "x"}), &HashMap::new()).is_none());
    }

    #[test]
    fn the_list_envelope_is_tagged() {
        let page = Paged::new(
            "position",
            vec![Position::from_json(&sample(), &HashMap::new()).unwrap()],
        );
        let v = serde_json::to_value(&page).unwrap();
        assert_eq!(v["schema"], "position-list/v1");
    }
}
