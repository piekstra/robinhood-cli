//! `rhd mcp`: Robinhood net worth, positions, activity and documents as MCP
//! tools (cli-common DESIGN.md §1.9, the MCP profile), for Claude Code,
//! Claude Desktop and any MCP client.
//!
//! Three read-only tools over the same reads and mappers the commands use:
//! `robinhood_portfolio` (`net-worth`'s per-account valuation and the
//! positions behind it), `robinhood_activity` (executed stock trades,
//! dividends and cash-sweep interest over a date range) and
//! `robinhood_documents` (statements and tax forms, listed, never
//! downloaded). Nothing here can write: the client underneath has no verb
//! but GET outside the login flow.
//!
//! Provider access goes through [`Source`], the per-target seam of
//! cli-common's MCP profile (DESIGN.md §2.3); the tests run every tool
//! offline against the fixtures through it. [`LiveSource`] uses the session
//! `rhd auth login --browser` stored for the selected profile, and only when
//! a tool is called: listing the tools touches no credential. It never signs
//! in itself: a missing or dead session is an auth error naming that command.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use pk_cli_core::{dates, CliError, RangeArgs};
use pk_cli_mcp::{
    parse_args, ListArgs, Page, PageRequest, Server, ToolDef, ToolError, ToolOutput, Toolset,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::dividends::{self, Dividend};
use crate::commands::fanout::{self, Scope};
use crate::commands::interest::{self, Interest};
use crate::commands::positions::{self, Position};
use crate::commands::transactions::{self, Transaction};
use crate::commands::{accounts, documents, instrument_id, instruments, networth, str_at, Ctx};
use crate::fixed::{from_fixed, mul_fixed, to_fixed};

pub const PORTFOLIO_TOOL: &str = "robinhood_portfolio";
pub const ACTIVITY_TOOL: &str = "robinhood_activity";
pub const DOCUMENTS_TOOL: &str = "robinhood_documents";

/// The activity kinds, as the `type` argument and each item's `type`.
const TRADE: &str = "trade";
const DIVIDEND: &str = "dividend";
const INTEREST: &str = "interest";

/// Where the tools get Robinhood's rows: the live API, or fixtures.
#[allow(async_fn_in_trait)] // deliberate: no `Send` bound, as in `Toolset`
pub trait Source {
    /// Every account row on the login with its number, closed ones included
    /// (`accounts::addressable_rows`).
    async fn accounts(&self) -> Result<Vec<(String, Value)>, CliError>;
    /// One account's current positions (`/positions/?nonzero=true`).
    async fn positions(&self, account: &str) -> Result<Vec<Value>, CliError>;
    /// Last-trade prices for instrument UUIDs, in 1/10⁸ units.
    async fn prices(
        &self,
        instruments: &BTreeSet<String>,
    ) -> Result<HashMap<String, i64>, CliError>;
    /// Ticker symbols for the instrument URLs on `rows`, keyed by URL.
    async fn symbols(&self, rows: &[&Value]) -> Result<HashMap<String, String>, CliError>;
    /// One account's stock orders updated on or after `since`.
    async fn orders(&self, account: &str, since: &str) -> Result<Vec<Value>, CliError>;
    /// Every dividend on the login.
    async fn dividends(&self) -> Result<Vec<Value>, CliError>;
    /// Every cash-sweep interest payment on the login.
    async fn interest(&self) -> Result<Vec<Value>, CliError>;
    /// Document rows, of one type when given.
    async fn documents(&self, kind: Option<&str>) -> Result<Vec<Value>, CliError>;
}

/// The live API, through the same [`Ctx`] the commands use.
///
/// One context, one read at a time: a lapsed access token is refreshed
/// inside `Ctx::access_token`, which rotates the stored refresh token, and
/// two calls refreshing at once would present the same one twice. The
/// shared client also keeps its request pacing across calls.
pub struct LiveSource {
    ctx: Mutex<Ctx>,
    /// Why no profile could be chosen, when none could: every call fails
    /// with it, so the user hears it through Claude rather than from a
    /// server that never started.
    unusable: Option<String>,
}

impl LiveSource {
    pub fn new(ctx: Ctx) -> Self {
        Self {
            ctx: Mutex::new(ctx),
            unusable: None,
        }
    }

    /// A source whose every call fails with `why` (an unresolvable profile).
    pub fn unusable(ctx: Ctx, why: String) -> Self {
        Self {
            ctx: Mutex::new(ctx),
            unusable: Some(why),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&Ctx, &str) -> Result<T, CliError>) -> Result<T, CliError> {
        if let Some(why) = &self.unusable {
            return Err(CliError::Other(format!(
                "no Robinhood login profile could be chosen: {why}"
            )));
        }
        let ctx = self.ctx.lock().unwrap_or_else(|e| e.into_inner());
        let token = ctx.access_token()?;
        f(&ctx, &token)
    }
}

/// Blocking inside `async fn` is deliberate: the stdio server polls each call
/// on its own blocking thread with no Tokio reactor (pk-cli-mcp's `Toolset`
/// contract), which is where `reqwest::blocking` belongs.
impl Source for LiveSource {
    async fn accounts(&self) -> Result<Vec<(String, Value)>, CliError> {
        self.with(accounts::addressable_rows)
    }

    async fn positions(&self, account: &str) -> Result<Vec<Value>, CliError> {
        self.with(|ctx, token| {
            ctx.rh.paginate(
                token,
                positions::PATH,
                &networth::positions_query(account),
                None,
            )
        })
    }

    async fn prices(
        &self,
        instruments: &BTreeSet<String>,
    ) -> Result<HashMap<String, i64>, CliError> {
        self.with(|ctx, token| networth::fetch_prices(ctx, token, instruments))
    }

    async fn symbols(&self, rows: &[&Value]) -> Result<HashMap<String, String>, CliError> {
        self.with(|ctx, token| instruments::resolve_symbols(ctx, token, rows))
    }

    async fn orders(&self, account: &str, since: &str) -> Result<Vec<Value>, CliError> {
        let range = RangeArgs {
            since: Some(since.to_string()),
            ..RangeArgs::default()
        };
        self.with(|ctx, token| {
            ctx.rh.paginate(
                token,
                transactions::PATH,
                &transactions::order_query(Some(account), &range),
                None,
            )
        })
    }

    async fn dividends(&self) -> Result<Vec<Value>, CliError> {
        self.with(|ctx, token| ctx.rh.paginate(token, dividends::PATH, &[], None))
    }

    async fn interest(&self) -> Result<Vec<Value>, CliError> {
        self.with(|ctx, token| ctx.rh.paginate(token, interest::PATH, &[], None))
    }

    async fn documents(&self, kind: Option<&str>) -> Result<Vec<Value>, CliError> {
        let query: Vec<(&'static str, String)> = kind
            .map(|k| vec![("type", k.to_string())])
            .unwrap_or_default();
        self.with(|ctx, token| ctx.rh.paginate(token, documents::PATH, &query, None))
    }
}

/// The toolset `rhd mcp` serves.
pub struct RobinhoodTools<S: Source> {
    source: S,
    /// The login profile the source reads, named in the sign-in remedy.
    profile: String,
}

impl<S: Source> RobinhoodTools<S> {
    pub fn new(source: S, profile: impl Into<String>) -> Self {
        Self {
            source,
            profile: profile.into(),
        }
    }

    #[cfg(test)]
    pub fn source(&self) -> &S {
        &self.source
    }

    /// A provider failure as a tool error; a sign-in failure names the
    /// browser login for this profile.
    fn err(&self, e: CliError) -> ToolError {
        match e {
            CliError::Auth(m) => ToolError::auth(m).with_fix(format!(
                "Ask the user to run `rhd auth login --browser --profile {}` in a terminal, \
                 then call the tool again. Tools never sign in or create credentials themselves",
                self.profile
            )),
            other => other.into(),
        }
    }
}

// ---- robinhood_portfolio ----------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortfolioArgs {
    /// Only this account (name or number).
    #[serde(default)]
    pub account: Option<String>,
    /// Only this symbol.
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct PortfolioFilter<'a> {
    account: Option<&'a str>,
    symbol: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct NetWorth {
    pub total: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liabilities: Option<String>,
    /// What the figures include: cash and equities (no options, no crypto).
    pub covers: Vec<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct AccountTotal {
    pub name: String,
    /// individual, ira_roth, ira_traditional, joint_tenancy_with_ros, ...
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub total: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct PositionItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub account: String,
    pub quantity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_buy_price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instrument_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PortfolioOut {
    pub net_worth: NetWorth,
    pub accounts: Vec<AccountTotal>,
    #[serde(flatten)]
    pub page: Page<PositionItem>,
}

// ---- robinhood_activity -----------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActivityArgs {
    /// First day, YYYY-MM-DD. Default: Jan 1 of until's year.
    #[serde(default)]
    pub since: Option<String>,
    /// Last day, YYYY-MM-DD. Default: today.
    #[serde(default)]
    pub until: Option<String>,
    /// Only this account (name or number).
    #[serde(default)]
    pub account: Option<String>,
    /// trade, dividend or interest. Default: all three.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// Only this symbol.
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct ActivityFilter<'a> {
    since: &'a str,
    until: &'a str,
    account: Option<&'a str>,
    kind: Option<&'a str>,
    symbol: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct ActivityItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// buy or sell.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    /// A trade's executed notional, a payment's amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Concise: only when not filled or paid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ActivityOut {
    pub since: String,
    pub until: String,
    #[serde(flatten)]
    pub page: Page<ActivityItem>,
}

// ---- robinhood_documents ----------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocumentsArgs {
    /// 1099, account_statement or trade_confirm.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// Dated on or after, YYYY-MM-DD.
    #[serde(default)]
    pub since: Option<String>,
    /// Dated on or before, YYYY-MM-DD.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct DocumentsFilter<'a> {
    kind: Option<&'a str>,
    since: Option<&'a str>,
    until: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct DocumentItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// For `rhd documents download <id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocumentsOut {
    #[serde(flatten)]
    pub page: Page<DocumentItem>,
}

// ---- the toolset ------------------------------------------------------------

impl<S: Source> Toolset for RobinhoodTools<S> {
    fn server(&self) -> Server {
        Server::new("rhd", env!("CARGO_PKG_VERSION"), "Robinhood", "robinhood").instructions(
            "Robinhood access here is read-only: no tool can trade, transfer or change \
             anything. Robinhood sign-in is through a browser: the command to ask for is `rhd \
             auth login --browser`. Values cover cash and stocks/ETFs; options and crypto are \
             not included. Amounts are USD decimal strings; keep every digit when adding them.",
        )
    }

    fn tools(&self) -> Vec<ToolDef> {
        vec![
            ToolDef::read(
                PORTFOLIO_TOOL,
                "Robinhood net worth and positions",
                "Shows the user's Robinhood net worth, each account's total and the stock \
                 positions held, valued at the last trade. Use it for what they own at \
                 Robinhood and its value. Returns net_worth, accounts and position items. \
                 Narrow with account or symbol.",
            )
            .input::<PortfolioArgs>()
            .output::<PortfolioOut>(),
            ToolDef::read(
                ACTIVITY_TOOL,
                "Robinhood activity",
                "Lists executed stock trades, dividends and cash interest in a date range, \
                 newest first. Use it for what happened in a period or a year's income. Items \
                 carry date, type, symbol, side, quantity, price, amount and account. Defaults \
                 to the year to date; narrow with account, type or symbol.",
            )
            .input::<ActivityArgs>()
            .output::<ActivityOut>(),
            ToolDef::read(
                DOCUMENTS_TOOL,
                "Robinhood documents",
                "Lists the user's Robinhood tax forms, statements and trade confirmations, \
                 newest first, without downloading them. Use it to see which 1099s or \
                 statements exist. Items carry date, name and type. Narrow with type (1099) \
                 or since/until.",
            )
            .input::<DocumentsArgs>()
            .output::<DocumentsOut>(),
        ]
    }

    async fn call(&self, name: &str, args: Value) -> Result<ToolOutput, ToolError> {
        match name {
            PORTFOLIO_TOOL => self.portfolio(parse_args(args)?).await,
            ACTIVITY_TOOL => self.activity(parse_args(args)?).await,
            DOCUMENTS_TOOL => self.documents(parse_args(args)?).await,
            other => Err(ToolError::other(format!("no handler for {other}"))),
        }
    }
}

impl<S: Source> RobinhoodTools<S> {
    async fn portfolio(&self, args: PortfolioArgs) -> Result<ToolOutput, ToolError> {
        let account = non_empty(args.account.as_deref());
        let symbol = non_empty(args.symbol.as_deref());
        let page = PageRequest::new(&args.list, &PortfolioFilter { account, symbol })?;
        let detailed = args.list.format().is_detailed();

        // A valuation reads open accounts only, as `rhd net-worth` does.
        let all = self.source.accounts().await.map_err(|e| self.err(e))?;
        let active: Vec<Named> = named(&all)
            .into_iter()
            .filter(|a| accounts::is_active_row(a.row))
            .collect();
        let scope = pick(&active, account)?;

        // Every account's holdings, each row verified as that account's,
        // before one price lookup covers them all.
        let mut held = Vec::with_capacity(scope.len());
        let mut wanted = BTreeSet::new();
        for acct in &scope {
            let rows = self
                .source
                .positions(acct.number)
                .await
                .map_err(|e| self.err(e))?;
            let holdings =
                networth::verified_holdings(&rows, acct.number).map_err(|e| self.err(e))?;
            for row in &rows {
                if let Some(id) = str_at(row, "instrument").as_deref().and_then(instrument_id) {
                    wanted.insert(id);
                }
            }
            held.push((acct, rows, holdings));
        }
        let prices = if wanted.is_empty() {
            HashMap::new()
        } else {
            self.source.prices(&wanted).await.map_err(|e| self.err(e))?
        };
        let all_rows: Vec<&Value> = held.iter().flat_map(|(_, rows, _)| rows.iter()).collect();
        let symbols = if all_rows.is_empty() {
            HashMap::new()
        } else {
            self.source
                .symbols(&all_rows)
                .await
                .map_err(|e| self.err(e))?
        };

        let mut per_account = Vec::with_capacity(held.len());
        let mut totals = Vec::with_capacity(held.len());
        let mut matched = Vec::new();
        for (acct, rows, holdings) in &held {
            let value = networth::holdings_value(acct.number, holdings, &prices)
                .map_err(|e| self.err(e))?;
            let (row, equity) =
                networth::account_row(acct.row, acct.number, value).map_err(|e| self.err(e))?;
            totals.push(AccountTotal {
                name: acct.name.clone(),
                kind: row.kind.clone(),
                total: row.total.amount.clone(),
                account_number: detailed.then(|| acct.number.to_string()),
            });
            per_account.push((row, equity));
            for raw in rows {
                let Some(p) = Position::from_json(raw, &symbols) else {
                    continue;
                };
                if symbol.is_some_and(|s| {
                    !p.symbol
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(s))
                }) {
                    continue;
                }
                matched.push(position_item(raw, p, acct, &prices, detailed));
            }
        }
        let rolled = networth::rollup(per_account);
        ToolOutput::new(&PortfolioOut {
            net_worth: NetWorth {
                total: rolled.total.amount,
                liabilities: rolled.liabilities.map(|m| m.amount),
                covers: rolled.covers.iter().map(|c| c.to_string()).collect(),
            },
            accounts: totals,
            page: page.page(matched, "account or symbol")?,
        })
    }

    async fn activity(&self, args: ActivityArgs) -> Result<ToolOutput, ToolError> {
        let (since, until) = window(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let account = non_empty(args.account.as_deref());
        let kind = non_empty(args.kind.as_deref()).map(str::to_ascii_lowercase);
        if let Some(k) = kind.as_deref() {
            if ![TRADE, DIVIDEND, INTEREST].contains(&k) {
                return Err(ToolError::usage(format!(
                    "type must be trade, dividend or interest, got `{k}`"
                )));
            }
        }
        let symbol = non_empty(args.symbol.as_deref());
        let page = PageRequest::new(
            &args.list,
            &ActivityFilter {
                since: &since,
                until: &until,
                account,
                kind: kind.as_deref(),
                symbol,
            },
        )?;
        let detailed = args.list.format().is_detailed();
        let wants = |k: &str| kind.as_deref().is_none_or(|w| w == k);
        // An undated row is kept, never dropped, as every list command keeps
        // it: losing a payment silently is the worse failure for tax work.
        let in_window = |d: Option<&str>| {
            d.is_none_or(|d| crate::commands::date_within(d, Some(&since), Some(&until)))
        };

        // History includes closed accounts: one can hold this year's trades.
        let all = self.source.accounts().await.map_err(|e| self.err(e))?;
        let every = named(&all);
        let scope = pick(&every, account)?;
        let name_of = |number: Option<&str>| -> Option<String> {
            let number = number?;
            every
                .iter()
                .find(|a| a.number == number)
                .map(|a| a.name.clone())
                .or_else(|| Some(number.to_string()))
        };
        // Dividends and interest come in one read for the whole login. With
        // no account named, every row is kept, a row naming no account too,
        // as `rhd dividends list` and `rhd interest list` keep them.
        let in_scope = |number: Option<String>| {
            account.is_none() || number.is_some_and(|n| scope.iter().any(|a| a.number == n))
        };

        let mut orders = Vec::new();
        if wants(TRADE) {
            for acct in &scope {
                let rows = self
                    .source
                    .orders(acct.number, &since)
                    .await
                    .map_err(|e| self.err(e))?;
                let tagged =
                    fanout::verify_and_tag(rows, &Scope::of(acct.number, acct.row), "order")
                        .map_err(|e| self.err(e))?;
                orders.extend(
                    tagged.into_iter().filter(|r| {
                        executed(r) && in_window(transactions::order_date(r).as_deref())
                    }),
                );
            }
        }
        let mut paid = Vec::new();
        if wants(DIVIDEND) {
            paid = self
                .source
                .dividends()
                .await
                .map_err(|e| self.err(e))?
                .into_iter()
                .filter(|r| {
                    in_scope(str_at(r, "account_number_rhs"))
                        && dividends::within(r, Some(&since), Some(&until))
                })
                .collect();
        }
        let mut swept = Vec::new();
        // Interest has no symbol, so a symbol filter would drop it all.
        if wants(INTEREST) && symbol.is_none() {
            swept = self
                .source
                .interest()
                .await
                .map_err(|e| self.err(e))?
                .into_iter()
                .filter(|r| {
                    in_scope(str_at(r, "account_number"))
                        && interest::within(r, Some(&since), Some(&until))
                })
                .collect();
        }

        let needing: Vec<&Value> = orders.iter().chain(paid.iter()).collect();
        let symbols = if needing.is_empty() {
            HashMap::new()
        } else {
            self.source
                .symbols(&needing)
                .await
                .map_err(|e| self.err(e))?
        };

        let mut items: Vec<ActivityItem> = Vec::new();
        for t in orders
            .iter()
            .filter_map(|r| Transaction::from_json(r, &symbols, false))
        {
            items.push(ActivityItem {
                date: t.date,
                kind: TRADE.into(),
                symbol: t.symbol,
                side: t.side,
                quantity: t.quantity,
                price: t.average_price.map(|m| m.amount),
                amount: t.executed_notional.map(|m| m.amount),
                state: t.state.filter(|s| detailed || s != "filled"),
                account: name_of(t.account_number.as_deref()),
                fees: t.fees.map(|m| m.amount).filter(|_| detailed),
                id: detailed.then_some(t.id),
            });
        }
        for d in paid.iter().filter_map(|r| Dividend::from_json(r, &symbols)) {
            items.push(ActivityItem {
                date: d.date,
                kind: DIVIDEND.into(),
                symbol: d.symbol,
                amount: d.amount.map(|m| m.amount),
                state: d
                    .state
                    .filter(|s| detailed || !matches!(s.as_str(), "paid" | "reinvested")),
                account: name_of(d.account_number.as_deref()),
                id: detailed.then_some(d.id),
                ..ActivityItem::default()
            });
        }
        for i in swept.iter().filter_map(Interest::from_json) {
            items.push(ActivityItem {
                date: i.date,
                kind: INTEREST.into(),
                amount: i.amount.map(|m| m.amount),
                account: name_of(i.account_number.as_deref()),
                id: detailed.then_some(i.id),
                ..ActivityItem::default()
            });
        }
        if let Some(s) = symbol {
            items.retain(|i| {
                i.symbol
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(s))
            });
        }
        // Newest first; an undated row (kept, never dropped) sorts last.
        items.sort_by(|a, b| b.date.cmp(&a.date));
        ToolOutput::new(&ActivityOut {
            since,
            until,
            page: page.page(items, "since/until, account, type or symbol")?,
        })
    }

    async fn documents(&self, args: DocumentsArgs) -> Result<ToolOutput, ToolError> {
        let kind = non_empty(args.kind.as_deref());
        if let Some(k) = kind {
            documents::validate_type(k)?;
        }
        let since = date_arg("since", non_empty(args.since.as_deref()))?;
        let until = date_arg("until", non_empty(args.until.as_deref()))?;
        if let (Some(s), Some(u)) = (&since, &until) {
            if s > u {
                return Err(ToolError::usage(format!(
                    "since ({s}) is after until ({u})"
                )));
            }
        }
        let page = PageRequest::new(
            &args.list,
            &DocumentsFilter {
                kind,
                since: since.as_deref(),
                until: until.as_deref(),
            },
        )?;
        let detailed = args.list.format().is_detailed();
        let range = RangeArgs {
            since: since.clone(),
            until: until.clone(),
            limit: None,
        };
        let rows = self.source.documents(kind).await.map_err(|e| self.err(e))?;
        let mut docs: Vec<_> = rows
            .iter()
            .filter_map(documents::to_document)
            .filter(|d| documents::date_in_range(d.date.as_deref(), &range))
            .collect();
        docs.sort_by(|a, b| b.date.cmp(&a.date));
        let matched = docs
            .into_iter()
            .map(|d| DocumentItem {
                date: d.date,
                name: d.name,
                kind: d.category,
                id: detailed.then_some(d.id),
            })
            .collect();
        ToolOutput::new(&DocumentsOut {
            page: page.page(matched, "type or since/until")?,
        })
    }
}

/// An account row with the name a person knows it by.
struct Named<'a> {
    number: &'a str,
    row: &'a Value,
    name: String,
}

/// Every account's name: its nickname, else its designation (`individual`,
/// `ira_roth`, ...). Where two would share a name, each takes the last four
/// characters of its number.
fn named(rows: &[(String, Value)]) -> Vec<Named<'_>> {
    let base = |row: &Value| {
        str_at(row, "nickname")
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .or_else(|| accounts::designation(row))
            .unwrap_or_else(|| "account".into())
    };
    let bases: Vec<String> = rows.iter().map(|(_, r)| base(r)).collect();
    rows.iter()
        .zip(&bases)
        .map(|((number, row), b)| {
            let shared = bases.iter().filter(|x| x.eq_ignore_ascii_case(b)).count() > 1;
            let name = if shared {
                let skip = number.chars().count().saturating_sub(4);
                let tail: String = number.chars().skip(skip).collect();
                format!("{b} …{tail}")
            } else {
                b.clone()
            };
            Named { number, row, name }
        })
        .collect()
}

/// The accounts `wanted` names (by number, or by name ignoring case), or
/// all of them when it names none. An unknown name is not found, listing the
/// names that exist.
fn pick<'a, 'r>(
    all: &'a [Named<'r>],
    wanted: Option<&str>,
) -> Result<Vec<&'a Named<'r>>, ToolError> {
    let Some(wanted) = wanted else {
        return Ok(all.iter().collect());
    };
    let hit: Vec<&Named> = all
        .iter()
        .filter(|a| a.number == wanted || a.name.eq_ignore_ascii_case(wanted))
        .collect();
    if hit.is_empty() {
        let names: Vec<&str> = all.iter().map(|a| a.name.as_str()).collect();
        return Err(ToolError::not_found(format!(
            "no Robinhood account named `{wanted}`; the accounts are: {}",
            names.join(", ")
        ))
        .with_fix("Call again with one of those names"));
    }
    Ok(hit)
}

/// One position with its value at the last trade. A position the price map
/// lacks never gets here: `holdings_value` has already refused the account.
fn position_item(
    raw: &Value,
    p: Position,
    acct: &Named,
    prices: &HashMap<String, i64>,
    detailed: bool,
) -> PositionItem {
    let id = p.instrument.as_deref().and_then(instrument_id);
    let price = id.as_ref().and_then(|i| prices.get(i)).copied();
    let market_value = str_at(raw, "quantity")
        .and_then(|q| to_fixed(&q))
        .zip(price)
        .and_then(|(q, px)| mul_fixed(q, px))
        .map(|v| from_fixed(v.into()).amount);
    PositionItem {
        symbol: p.symbol,
        account: acct.name.clone(),
        quantity: p.quantity,
        market_value,
        average_buy_price: p.average_buy_price.map(|m| m.amount),
        price: price
            .filter(|_| detailed)
            .map(|px| from_fixed(px.into()).amount),
        instrument_id: id.filter(|_| detailed),
    }
}

/// A trade that moved shares: filled, or a partial fill on a cancelled
/// order (transactions.rs, "the consumer contract"). An order with no state
/// is kept, as unknown rather than not filled.
fn executed(order: &Value) -> bool {
    let state = str_at(order, "state");
    if state.is_none() || state.as_deref() == Some("filled") {
        return true;
    }
    str_at(order, "cumulative_quantity")
        .and_then(|q| to_fixed(&q))
        .is_some_and(|q| q > 0)
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// A date argument, zero-padded (`2026-1-5` is `2026-01-05`) so the string
/// comparisons that filter rows are date comparisons.
fn date_arg(name: &str, v: Option<&str>) -> Result<Option<String>, ToolError> {
    v.map(|d| {
        dates::parse_iso(d).map(dates::fmt_iso).map_err(|_| {
            ToolError::usage(format!("{name} must be a date as YYYY-MM-DD, got `{d}`"))
        })
    })
    .transpose()
}

/// The inclusive window, defaulting to the year to date.
fn window(since: Option<&str>, until: Option<&str>) -> Result<(String, String), ToolError> {
    let since = date_arg("since", since)?;
    let until = date_arg("until", until)?.unwrap_or_else(|| dates::fmt_iso(dates::today()));
    let since = since.unwrap_or_else(|| format!("{}-01-01", &until[..4]));
    if since > until {
        return Err(ToolError::usage(format!(
            "since ({since}) is after until ({until})"
        )));
    }
    Ok((since, until))
}

#[cfg(test)]
mod tests;
