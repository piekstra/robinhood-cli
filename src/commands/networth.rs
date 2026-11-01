//! `rhd net-worth` — the login's Robinhood net worth (`net-worth/v1`).
//!
//! Per-account equity is **computed from the provider's truthfully-scoped
//! parts**: the account row's own `portfolio_cash`, plus quantity × price
//! over `/positions/?nonzero=true&account_number=<n>`, priced by a batched
//! `/marketdata/quotes/` lookup. There is no shortcut: both portfolio
//! endpoints that promise a per-account total **ignore their account
//! parameter and echo the primary account** (docs/api.md §3.8 has the full
//! truth table — read it before "simplifying" this back to a portfolio
//! read). Positions scope truthfully and every row names its own account,
//! so per-row verification makes lying impossible; a row for the wrong
//! account is refused loudly, never absorbed.
//!
//! The DTO is the family's `net-worth/v1` shape (`total`, `assets`,
//! `liabilities` omit-if-none, per-account `accounts[]` rows), the same
//! vocabulary `m1f net-worth` emits, so an asset-capturing consumer needs one
//! registry row per provider, not per-provider glue.

use std::collections::{BTreeSet, HashMap};

use pk_cli_core::{CliError, Money};
use serde::Serialize;
use serde_json::Value;

use crate::commands::accounts::{self, designation};
use crate::commands::{emit_one, instrument_id, money_at, positions, str_at, Ctx};
use crate::fixed::{from_fixed, mul_fixed, to_fixed};

/// Community-standard batch quote endpoint
/// (`?instruments=<url>,<url>,…`). **UNVERIFIED-LIVE** — modelled on the
/// community record only; a shape surprise here fails loudly (exit 5),
/// never as a silent $0 (docs/api.md §3.8).
pub const QUOTES_PATH: &str = "/marketdata/quotes/";

/// Instruments per quote request — same batching rationale as the symbol
/// lookup: one request per holding against a rate-limited API is the wrong
/// trade.
const QUOTE_BATCH: usize = 25;

/// The positions query for one account. `nonzero=true` keeps closed lots
/// out of a valuation; `account_number` scoping is **LIVE-VERIFIED
/// truthful** (2026-08-21: distinct row counts per account, each row naming
/// its own account) — unlike the portfolio endpoints' parameter, which is
/// ignored (docs/api.md §3.8).
fn positions_query(account_number: &str) -> Vec<(&'static str, String)> {
    vec![
        ("nonzero", "true".to_string()),
        ("account_number", account_number.to_string()),
    ]
}

/// What the figures in this DTO include: cash and cash-equity holdings.
///
/// `/positions/` covers stocks/ETFs only — options and crypto live on other
/// endpoints this command does not yet value (docs/api.md §3.3, §7) — so the
/// scope is **stated in-band** rather than implied. Every row-level omission
/// in this module is a loud refusal; without this field the asset-class
/// narrowing would be the one silent omission, and a consumer would read
/// `total` as "everything at Robinhood" when it is not.
///
/// A slice, not an array: valuing options/crypto later (docs/api.md §7)
/// appends an element here without touching the DTO type or any
/// construction site.
const COVERS: &[&str] = &["cash", "equities"];

/// The `net-worth/v1` DTO. `total` is net (`portfolio_cash` in a margin
/// account already reflects any margin debit, so provider-internal borrowing
/// nets out inside its account rather than appearing here as a liability);
/// `liabilities` only appears in the odd case of an account whose whole
/// equity is negative. `covers` declares the figure's scope ([`COVERS`]).
#[derive(Debug, Serialize)]
pub struct NetWorth {
    pub total: Money,
    pub assets: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liabilities: Option<Money>,
    /// Asset classes included in the figures — see [`COVERS`].
    pub covers: &'static [&'static str],
    pub accounts: Vec<AccountRow>,
}

/// One brokerage account's slice of the rollup.
#[derive(Debug, Serialize)]
pub struct AccountRow {
    pub account_number: String,
    /// The provider's account designation (`individual`, `ira_roth`, …),
    /// falling back to `cash`/`margin` when the richer field is absent.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// This account's equity — `portfolio_cash` + the market value of its
    /// verified holdings.
    pub total: Money,
}

/// One verified holding, ready to price.
#[derive(Debug, PartialEq)]
struct Holding {
    /// Quantity in 1/10⁸ units (fractional shares are real).
    quantity: i64,
    /// The instrument UUID — the join key to its quote.
    instrument: String,
}

/// `explicit_account` is the `-a` flag / `RHD_ACCOUNT` env for **this
/// invocation** — never the profile's persisted default account.
///
/// That distinction is deliberate and load-bearing: every other read
/// honoring a persisted default narrows harmlessly, but this command's
/// contract is completeness, and a config default silently turning the
/// "household" total into one account's balance is exactly the quiet
/// misreport the honesty rules exist to prevent. So the persisted default is
/// ignored here, and only an explicit selection narrows the rollup (the
/// [`scoped`] tests pin the semantics).
pub fn show(ctx: &Ctx, explicit_account: Option<&str>) -> Result<(), CliError> {
    let token = ctx.access_token()?;

    // Reuse the accounts reader — `default_to_all_accounts=true` is what
    // keeps a household member's IRA or joint account from silently missing
    // from a figure whose whole point is completeness (docs/api.md §3.2).
    let active = scoped(accounts::active_rows(ctx, &token)?, explicit_account)?;

    // Gather every account's verified holdings first, so one batched quote
    // pass prices the union of instruments.
    let mut gathered = Vec::with_capacity(active.len());
    let mut instruments = BTreeSet::new();
    for (number, acct) in &active {
        let rows = ctx
            .rh
            .paginate(&token, positions::PATH, &positions_query(number), None)?;
        let holdings = verified_holdings(&rows, number)?;
        for h in &holdings {
            instruments.insert(h.instrument.clone());
        }
        gathered.push((number, acct, holdings));
    }

    let prices = fetch_prices(ctx, &token, &instruments)?;

    let mut per_account = Vec::with_capacity(gathered.len());
    for (number, acct, holdings) in gathered {
        let value = holdings_value(number, &holdings, &prices)?;
        per_account.push(account_row(acct, number, value)?);
    }

    emit_one("net-worth", &rollup(per_account), ctx.common.json);
    Ok(())
}

/// Narrow the active accounts (keyed by account number) to an explicit
/// selection, or keep them all.
///
/// Pure, so the scoping semantics — including "no selection means every
/// account" — are pinned offline and can't drift back to honoring a
/// persisted default.
fn scoped(
    mut active: Vec<(String, Value)>,
    wanted: Option<&str>,
) -> Result<Vec<(String, Value)>, CliError> {
    if let Some(wanted) = wanted {
        active.retain(|(number, _)| number == wanted);
        if active.is_empty() {
            return Err(CliError::NotFound(format!(
                "no active brokerage account `{wanted}` in this login — run `rhd accounts list`"
            )));
        }
    }
    if active.is_empty() {
        return Err(CliError::Upstream(
            "Robinhood returned no active brokerage accounts to value — if this login really \
             has none that is new information; otherwise the accounts shape has changed \
             (docs/api.md §3.2)"
                .into(),
        ));
    }
    Ok(active)
}

/// Verify and extract the holdings from one account's positions listing.
///
/// Every row must name the account it was requested for. This is the rail
/// that caught the portfolio endpoints lying (docs/api.md §3.8): if the
/// `account_number` filter is ever ignored the way the portfolio parameter
/// is, rows for another account appear here and the whole read is refused —
/// reporting one account's balance under another's number is worse than
/// failing. Rows that cannot be verified (no account_number) or valued (no
/// quantity/instrument) are refusals too, never silent omissions that would
/// understate the account. Pure, so all of it is pinned offline.
fn verified_holdings(rows: &[Value], number: &str) -> Result<Vec<Holding>, CliError> {
    rows.iter()
        .map(|r| {
            let owner = str_at(r, "account_number").ok_or_else(|| {
                CliError::Upstream(format!(
                    "a position row in account {number}'s listing carries no account_number — \
                     cannot verify whose balance this is; refusing to value it \
                     (docs/api.md §3.8)"
                ))
            })?;
            if owner != number {
                return Err(CliError::Upstream(format!(
                    "the positions listing for account {number} returned a row belonging to a \
                     different account — the account_number filter was ignored; refusing to \
                     report another account's balance (docs/api.md §3.8)"
                )));
            }
            let quantity = str_at(r, "quantity")
                .and_then(|q| to_fixed(&q))
                .ok_or_else(|| {
                    CliError::Upstream(format!(
                        "a position in account {number} carries no usable quantity — refusing \
                         to value an account with an uncountable holding (docs/api.md §3.8)"
                    ))
                })?;
            let instrument = str_at(r, "instrument")
                .as_deref()
                .and_then(instrument_id)
                .ok_or_else(|| {
                    CliError::Upstream(format!(
                        "a position in account {number} names no instrument — refusing to \
                         value an account with an unidentifiable holding (docs/api.md §3.8)"
                    ))
                })?;
            Ok(Holding {
                quantity,
                instrument,
            })
        })
        .collect()
}

/// Batch-fetch prices for a set of instrument UUIDs, keyed by UUID.
///
/// A quotes envelope without a `results` array is a shape surprise and is
/// named as such — degrading it into per-holding "no quote" errors would
/// hide the real cause from the user.
fn fetch_prices(
    ctx: &Ctx,
    token: &str,
    instruments: &BTreeSet<String>,
) -> Result<HashMap<String, i64>, CliError> {
    let mut prices = HashMap::new();
    let ids: Vec<&String> = instruments.iter().collect();
    for chunk in ids.chunks(QUOTE_BATCH) {
        let urls: Vec<String> = chunk
            .iter()
            .map(|id| format!("{}/instruments/{id}/", ctx.rh.base()))
            .collect();
        let body = ctx.rh.get(
            token,
            &ctx.rh.url(QUOTES_PATH),
            &[("instruments", urls.join(","))],
        )?;
        let rows = body
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CliError::Upstream(
                    "the quotes response carried no results array — the /marketdata/quotes/ \
                 shape may have changed; see docs/api.md §3.8"
                        .into(),
                )
            })?;
        prices.extend(price_map(rows));
    }
    Ok(prices)
}

/// Project a quotes `results` array into instrument-UUID → price.
///
/// Pure, so the one **UNVERIFIED-LIVE** shape in the pipeline gets the same
/// offline pin as everything else (the unit tests feed it the quotes
/// fixture verbatim). Rows join by `instrument_id`, falling back to the
/// UUID out of the `instrument` URL. **Null** entries (unquotable
/// instruments) and rows without a resolvable price never enter the map —
/// the absence then surfaces as [`holdings_value`]'s loud per-holding
/// error, not a silent $0.
fn price_map(rows: &[Value]) -> HashMap<String, i64> {
    let mut prices = HashMap::new();
    for q in rows {
        let key = str_at(q, "instrument_id")
            .or_else(|| str_at(q, "instrument").as_deref().and_then(instrument_id));
        if let (Some(key), Some(price)) = (key, quote_price(q)) {
            prices.insert(key, price);
        }
    }
    prices
}

/// The price a quote offers, in 1/10⁸ units: `last_trade_price`, falling
/// back to `last_extended_hours_trade_price` when the regular one is absent
/// — the regular-session print is the primary because it is always present
/// during and after a session, while the extended field is null outside
/// extended hours. A quote carrying neither yields `None`, which the caller
/// treats as unpriceable (loud), never as $0.
fn quote_price(quote: &Value) -> Option<i64> {
    money_at(quote, "last_trade_price")
        .or_else(|| money_at(quote, "last_extended_hours_trade_price"))
        .and_then(|m| to_fixed(&m.amount))
}

/// Value one account's holdings against the price map.
///
/// A holding without a price is a **refusal** — omitting it would silently
/// understate the account, which is the exact failure this command exists
/// to avoid.
fn holdings_value(
    number: &str,
    holdings: &[Holding],
    prices: &HashMap<String, i64>,
) -> Result<i64, CliError> {
    let mut sum: i64 = 0;
    for h in holdings {
        let price = prices.get(&h.instrument).ok_or_else(|| {
            CliError::Upstream(format!(
                "no quote for instrument {} (account {number}) — cannot value the position, \
                 and omitting it would understate the account; see docs/api.md §3.8",
                h.instrument
            ))
        })?;
        let value = mul_fixed(h.quantity, *price)
            .and_then(|v| sum.checked_add(v))
            .ok_or_else(|| {
                CliError::Upstream(format!(
                    "valuing account {number} overflowed the fixed-point range — see \
                     docs/api.md §3.8"
                ))
            })?;
        sum = value;
    }
    Ok(sum)
}

/// One account's DTO row plus its equity in fixed-point units — the number
/// travels as an `i64` so [`rollup`] never has to re-parse the rendered
/// string.
///
/// Equity = `portfolio_cash` + the holdings value. `portfolio_cash` comes
/// from the account's **own** row, which makes it inherently per-account —
/// unlike the portfolio endpoints (docs/api.md §3.8). Its absence is a loud
/// shape-change error, never a $0 assumption.
fn account_row(
    account: &Value,
    number: &str,
    holdings_value: i64,
) -> Result<(AccountRow, i64), CliError> {
    let cash = money_at(account, "portfolio_cash")
        .and_then(|m| to_fixed(&m.amount))
        .ok_or_else(|| {
            CliError::Upstream(format!(
                "the account row for {number} carried no usable portfolio_cash — the shape \
                 may have changed; see docs/api.md §3.8"
            ))
        })?;
    let equity = cash.checked_add(holdings_value).ok_or_else(|| {
        CliError::Upstream(format!(
            "account {number}'s equity overflowed the fixed-point range — see docs/api.md §3.8"
        ))
    })?;
    Ok((
        AccountRow {
            account_number: number.to_string(),
            // The shared reading, so this DTO's `type` and `account-list/v1`'s
            // `kind` can never disagree about the same account.
            kind: designation(account),
            total: from_fixed(equity.into()),
        },
        equity,
    ))
}

/// Sum the per-account equities into the household figures. Infallible: the
/// equities arrive as the same fixed-point values [`account_row`] rendered,
/// and the accumulation runs in `i128` (a sum of `i64` values cannot
/// overflow it).
///
/// Integer math at 8-digit fixed point ([`crate::fixed`]) — no float ever touches a
/// balance, and fractional digits survive the sum exactly. Client-side
/// because Robinhood exposes **no truthful household or per-account total
/// endpoint at all** (docs/api.md §3.8). `assets` collects the accounts
/// standing positive; an account whose whole equity is negative (a margin
/// call scenario) lands in `liabilities` instead of silently shrinking
/// "assets".
fn rollup(accounts: Vec<(AccountRow, i64)>) -> NetWorth {
    let mut assets: i128 = 0;
    let mut liabilities: i128 = 0;
    for (_, equity) in &accounts {
        let v = i128::from(*equity);
        if v >= 0 {
            assets += v;
        } else {
            liabilities += -v;
        }
    }
    NetWorth {
        total: from_fixed(assets - liabilities),
        assets: from_fixed(assets),
        liabilities: (liabilities > 0).then(|| from_fixed(liabilities)),
        covers: COVERS,
        accounts: accounts.into_iter().map(|(row, _)| row).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::{FRAC_DIGITS, SCALE};
    use serde_json::json;

    // Dummies per tests/fixtures/README.md — never a real account or balance.
    fn margin_account() -> Value {
        json!({
            "account_number": "SAMPLE01",
            "type": "margin",
            "brokerage_account_type": "individual",
            "portfolio_cash": "500.0000",
            "deactivated": false
        })
    }

    fn position(owner: &str, quantity: &str, instrument: &str) -> Value {
        json!({
            "account_number": owner,
            "account": format!("https://api.robinhood.com/accounts/{owner}/"),
            "quantity": quantity,
            "instrument":
                format!("https://api.robinhood.com/instruments/{instrument}/"),
            "average_buy_price": "150.0000"
        })
    }

    const INST_1: &str = "00000000-0000-4000-8000-000000000001";
    const INST_2: &str = "00000000-0000-4000-8000-000000000002";

    // ------------------------------------------------------ holdings + rails

    #[test]
    fn holdings_are_extracted_and_verified() {
        let rows = vec![
            position("SAMPLE01", "10.00000000", INST_1),
            position("SAMPLE01", "0.50000000", INST_2),
        ];
        let holdings = verified_holdings(&rows, "SAMPLE01").unwrap();
        assert_eq!(holdings.len(), 2);
        assert_eq!(holdings[0].quantity, 10 * SCALE);
        assert_eq!(holdings[0].instrument, INST_1);
        assert_eq!(holdings[1].quantity, SCALE / 2);
    }

    /// The param-ignored trap, pinned: a listing whose rows belong to a
    /// different account means the server ignored `account_number` — the
    /// exact lie the portfolio endpoints told live (2026-08-21). Refuse;
    /// never report one account's balance under another's number.
    #[test]
    fn rows_for_the_wrong_account_are_refused() {
        let rows = vec![position("SAMPLE01", "10.00000000", INST_1)];
        let err = verified_holdings(&rows, "SAMPLE03").unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("filter was ignored"));
    }

    /// A row that cannot be verified or valued is a refusal, not a silent
    /// omission that would understate the account.
    #[test]
    fn unverifiable_or_unvaluable_rows_are_refused() {
        let mut no_owner = position("SAMPLE01", "10.00000000", INST_1);
        no_owner.as_object_mut().unwrap().remove("account_number");
        let err = verified_holdings(&[no_owner], "SAMPLE01").unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("no account_number"));

        let mut no_qty = position("SAMPLE01", "10.00000000", INST_1);
        no_qty.as_object_mut().unwrap().remove("quantity");
        assert_eq!(
            verified_holdings(&[no_qty], "SAMPLE01")
                .unwrap_err()
                .exit_code(),
            5
        );

        let mut no_inst = position("SAMPLE01", "10.00000000", INST_1);
        no_inst.as_object_mut().unwrap().remove("instrument");
        assert_eq!(
            verified_holdings(&[no_inst], "SAMPLE01")
                .unwrap_err()
                .exit_code(),
            5
        );
    }

    #[test]
    fn an_account_with_no_positions_has_zero_holdings() {
        assert!(verified_holdings(&[], "SAMPLE01").unwrap().is_empty());
    }

    // -------------------------------------------------------------- pricing

    #[test]
    fn quote_price_prefers_the_regular_session_print() {
        let q = json!({
            "last_trade_price": "155.0000",
            "last_extended_hours_trade_price": "155.2500"
        });
        assert_eq!(quote_price(&q), Some(155 * SCALE));
    }

    /// The documented fallback: outside a regular session shape the
    /// extended-hours print stands in when the regular one is absent.
    #[test]
    fn quote_price_falls_back_to_extended_hours() {
        let q = json!({
            "last_trade_price": null,
            "last_extended_hours_trade_price": "25.7500"
        });
        assert_eq!(quote_price(&q), Some(2_575_000_000));
        // Neither price → unpriceable, which the caller raises loudly.
        assert_eq!(quote_price(&json!({ "symbol": "SAMPL" })), None);
    }

    /// The one UNVERIFIED-LIVE shape in the pipeline, pinned against the
    /// repo's own fixture: this is exactly what the wire would feed
    /// `price_map`, including the null entry for an unquotable instrument
    /// and a row whose only price is the extended-hours print.
    #[test]
    fn price_map_reads_the_quotes_fixture_the_way_the_wire_would() {
        let path = format!("{}/tests/fixtures/quotes.json", env!("CARGO_MANIFEST_DIR"));
        let body: Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("fixture")).unwrap();
        let rows = body["results"].as_array().expect("results").clone();
        assert!(rows.iter().any(Value::is_null), "fixture keeps a null row");

        let prices = price_map(&rows);
        assert_eq!(prices.len(), 2, "null entries never enter the map");
        // Regular print for SAMPL, extended-hours fallback for TESTF.
        assert_eq!(prices.get(INST_1).copied(), Some(155 * SCALE));
        assert_eq!(prices.get(INST_2).copied(), Some(2_575_000_000));
    }

    /// The join key: `instrument_id` when present, else the UUID out of the
    /// `instrument` URL — and both spellings of the same quote land on one
    /// key. Rows with no usable key or price are skipped (their absence is
    /// [`holdings_value`]'s loud error, not a wrong entry here).
    #[test]
    fn price_map_joins_by_either_key_and_skips_the_unusable() {
        let rows = vec![
            // URL only — no instrument_id field.
            json!({
                "instrument":
                    format!("https://api.robinhood.com/instruments/{INST_1}/"),
                "last_trade_price": "10.000000"
            }),
            // Direct id only.
            json!({ "instrument_id": INST_2, "last_trade_price": "20.000000" }),
            Value::Null,
            // A key without any price never produces an entry.
            json!({ "instrument_id": INST_2, "symbol": "TESTF" }),
        ];
        let prices = price_map(&rows);
        assert_eq!(prices.get(INST_1).copied(), Some(10 * SCALE));
        assert_eq!(prices.get(INST_2).copied(), Some(20 * SCALE));
        assert_eq!(prices.len(), 2);
    }

    #[test]
    fn holdings_are_valued_at_quantity_times_price() {
        let holdings = vec![
            Holding {
                quantity: 10 * SCALE,
                instrument: INST_1.into(),
            },
            Holding {
                quantity: SCALE / 2, // 0.5 shares
                instrument: INST_2.into(),
            },
        ];
        let prices = HashMap::from([
            (INST_1.to_string(), 155 * SCALE),
            (INST_2.to_string(), 25 * SCALE),
        ]);
        // 10 × 155 + 0.5 × 25 = 1562.50
        assert_eq!(
            holdings_value("SAMPLE01", &holdings, &prices).unwrap(),
            156_250 * SCALE / 100
        );
        // No holdings values to exactly zero.
        assert_eq!(holdings_value("SAMPLE01", &[], &prices).unwrap(), 0);
    }

    /// A missing quote must fail the read — omitting the position would
    /// silently understate the account.
    #[test]
    fn a_missing_quote_is_a_loud_refusal_not_a_zero() {
        let holdings = vec![Holding {
            quantity: SCALE,
            instrument: INST_1.into(),
        }];
        let err = holdings_value("SAMPLE01", &holdings, &HashMap::new()).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains(INST_1));
        assert!(err.to_string().contains("SAMPLE01"));
    }

    // ------------------------------------------------------- the DTO row

    #[test]
    fn an_account_row_is_cash_plus_holdings() {
        // 500 cash + 1550 holdings = 2050, designation preferred over type.
        let (row, equity) = account_row(&margin_account(), "SAMPLE01", 1550 * SCALE).unwrap();
        assert_eq!(row.account_number, "SAMPLE01");
        assert_eq!(row.kind.as_deref(), Some("individual"));
        assert_eq!(row.total.amount, "2050.00");
        assert_eq!(row.total.currency, "USD");
        // The fixed-point value travels with the row — the rendered string
        // and the number the rollup sums can never disagree.
        assert_eq!(equity, 2050 * SCALE);
    }

    #[test]
    fn the_account_designation_falls_back_to_cash_or_margin() {
        let mut acct = margin_account();
        acct.as_object_mut()
            .unwrap()
            .remove("brokerage_account_type");
        let (row, _) = account_row(&acct, "SAMPLE01", 0).unwrap();
        assert_eq!(row.kind.as_deref(), Some("margin"));
    }

    /// Missing cash is a shape-change error, never a $0 assumption.
    #[test]
    fn missing_portfolio_cash_is_a_loud_upstream_error() {
        let mut acct = margin_account();
        acct.as_object_mut().unwrap().remove("portfolio_cash");
        let err = account_row(&acct, "SAMPLE01", 0).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("SAMPLE01"));
    }

    /// A margin debit shows up as negative portfolio cash and must subtract,
    /// not error: equity = holdings + (negative) cash.
    #[test]
    fn negative_portfolio_cash_nets_against_holdings() {
        let mut acct = margin_account();
        acct["portfolio_cash"] = json!("-100.0000");
        let (row, _) = account_row(&acct, "SAMPLE01", 1550 * SCALE).unwrap();
        assert_eq!(row.total.amount, "1450.00");
    }

    // ------------------------------------------------------------- scoping

    /// The scoping contract: no explicit selection means **every** account.
    /// This is what keeps a profile's persisted default account — which the
    /// dispatcher never passes in — from silently narrowing the household
    /// figure to one account's balance.
    #[test]
    fn no_explicit_selection_keeps_every_account() {
        let all = vec![
            ("SAMPLE01".to_string(), json!({})),
            ("SAMPLE02".to_string(), json!({})),
        ];
        assert_eq!(scoped(all.clone(), None).unwrap().len(), 2);
        // An explicit selection narrows to exactly that account...
        let one = scoped(all.clone(), Some("SAMPLE02")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].0, "SAMPLE02");
        // ...and an unknown one is not-found (exit 4), never an empty $0 DTO.
        assert_eq!(scoped(all, Some("SAMPLE99")).unwrap_err().exit_code(), 4);
    }

    /// No active accounts at all is an upstream surprise, not a $0 login.
    #[test]
    fn an_empty_account_listing_is_a_loud_upstream_error() {
        assert_eq!(scoped(Vec::new(), None).unwrap_err().exit_code(), 5);
    }

    // -------------------------------------------------------------- rollup

    /// A rollup entry the way [`account_row`] produces one: the rendered
    /// row plus the same value in fixed-point units.
    fn entry(number: &str, amount: &str) -> (AccountRow, i64) {
        let fixed = to_fixed(amount).expect("test amounts are valid decimals");
        (
            AccountRow {
                account_number: number.into(),
                kind: Some("individual".into()),
                total: from_fixed(fixed.into()),
            },
            fixed,
        )
    }

    #[test]
    fn the_rollup_sums_accounts_and_omits_absent_liabilities() {
        let nw = rollup(vec![
            entry("SAMPLE01", "2000.00"),
            entry("SAMPLE02", "250.50"),
        ]);
        assert_eq!(nw.total.amount, "2250.50");
        assert_eq!(nw.assets.amount, "2250.50");
        assert!(
            nw.liabilities.is_none(),
            "no debt renders as absent, not $0"
        );
        assert_eq!(nw.accounts.len(), 2);
    }

    /// An account standing negative (margin-call territory) is a liability,
    /// not a quiet subtraction from "assets".
    #[test]
    fn a_negative_account_lands_in_liabilities() {
        let nw = rollup(vec![
            entry("SAMPLE01", "2000.00"),
            entry("SAMPLE02", "-150.25"),
        ]);
        assert_eq!(nw.assets.amount, "2000.00");
        assert_eq!(nw.liabilities.as_ref().unwrap().amount, "150.25");
        assert_eq!(nw.total.amount, "1849.75");
    }

    /// The regression behind the first 2026-08-21 live failure: an equity
    /// with more than four fractional digits must sum, not error.
    #[test]
    fn more_than_four_fraction_digits_survive_the_rollup() {
        let nw = rollup(vec![
            entry("SAMPLE01", "1234.567856"),
            entry("SAMPLE02", "0.000001"),
        ]);
        assert_eq!(nw.total.amount, "1234.567857");
    }

    /// Sub-cent digits are real on this provider and must survive the sum.
    #[test]
    fn sub_cent_precision_survives_the_rollup() {
        let nw = rollup(vec![
            entry("SAMPLE01", "0.0001"),
            entry("SAMPLE02", "0.0002"),
        ]);
        assert_eq!(nw.total.amount, "0.0003");
        // ...while whole-cent figures stay two-decimal.
        let nw = rollup(vec![entry("SAMPLE01", "10.50")]);
        assert_eq!(nw.total.amount, "10.50");
    }

    /// The i128 accumulator cannot overflow on sums of i64 equities — the
    /// extreme edge renders rather than wrapping or erroring.
    #[test]
    fn the_rollup_survives_extreme_balances() {
        let nw = rollup(vec![
            (
                AccountRow {
                    account_number: "SAMPLE01".into(),
                    kind: None,
                    total: from_fixed(i64::MAX.into()),
                },
                i64::MAX,
            ),
            (
                AccountRow {
                    account_number: "SAMPLE02".into(),
                    kind: None,
                    total: from_fixed(i64::MAX.into()),
                },
                i64::MAX,
            ),
        ]);
        assert_eq!(
            to_fixed_i128(&nw.total.amount),
            2 * i128::from(i64::MAX),
            "the household total is the exact sum"
        );
    }

    /// Parse helper for the extreme-balance test only: `to_fixed` is
    /// deliberately i64-bounded for wire values.
    fn to_fixed_i128(amount: &str) -> i128 {
        let (int, frac) = amount.split_once('.').unwrap_or((amount, ""));
        let frac_padded = format!("{frac:0<FRAC_DIGITS$}");
        int.parse::<i128>().unwrap() * i128::from(SCALE) + frac_padded.parse::<i128>().unwrap()
    }

    #[test]
    fn the_dto_serializes_the_family_shape() {
        let nw = rollup(vec![
            entry("SAMPLE01", "2000.00"),
            entry("SAMPLE02", "-1.00"),
        ]);
        let v = serde_json::to_value(&nw).unwrap();
        // `emit_one` adds the schema tag; the payload carries the figures.
        assert_eq!(v["total"]["amount"], "1999.00");
        assert_eq!(v["assets"]["amount"], "2000.00");
        assert_eq!(v["liabilities"]["amount"], "1.00");
        // The scope is declared in-band: this figure is cash + equities,
        // not "everything at Robinhood" (options/crypto are not valued).
        assert_eq!(v["covers"], json!(["cash", "equities"]));
        assert_eq!(v["accounts"][0]["account_number"], "SAMPLE01");
        assert_eq!(v["accounts"][0]["type"], "individual");
        assert_eq!(v["accounts"][0]["total"]["amount"], "2000.00");
    }
}
