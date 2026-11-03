//! `rhd` — read-only CLI for Robinhood brokerage accounts.
//!
//! Conforms to `piekstra-cli/1` (see `cli-common/DESIGN.md`). This file owns
//! the clap tree and the exit-code mapping; `client.rs` owns HTTP and the auth
//! dance, `config.rs` the non-secret settings and the multi-login profile
//! model, and `commands/*` one module per command group.
//!
//! Robinhood publishes no public retail API. Everything here is built against
//! community reverse-engineering — see `docs/api.md`, including which parts
//! are still UNVERIFIED-LIVE.

mod capture;
mod client;
mod commands;
mod config;
mod fixed;
mod mcp;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::{LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::BrowserArgs;
use pk_cli_config::ConfigStore;
use pk_cli_core::{output, CliError, CommonArgs, RangeArgs};
use pk_cli_http::ApiArgs;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

use crate::config::{Config, BIN, REPO};

/// Read-only access to Robinhood brokerage accounts (conforms to piekstra-cli/1).
///
/// Unofficial: Robinhood publishes no public API. See docs/api.md.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    /// Named login profile — which household member's Robinhood login to use.
    ///
    /// Distinct from --account, which picks a brokerage account *within* one
    /// login. Optional when only one profile is configured.
    #[arg(
        short = 'p',
        long,
        global = true,
        value_name = "NAME",
        env = "RHD_PROFILE"
    )]
    profile: Option<String>,

    /// Brokerage account number to act on, within the selected profile.
    #[arg(
        short = 'a',
        long,
        global = true,
        value_name = "ID",
        env = "RHD_ACCOUNT"
    )]
    account: Option<String>,

    /// Override the config file location.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Credential management and session status.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Named login profiles — one per household Robinhood login.
    #[command(subcommand)]
    Profiles(ProfilesCmd),
    /// Non-secret settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Brokerage accounts within the selected login.
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Current holdings.
    #[command(subcommand)]
    Positions(PositionsCmd),
    /// Open option positions (priced at the mark).
    #[command(subcommand)]
    Options(OptionsCmd),
    /// Order/settlement history — the realized-gains raw material.
    #[command(subcommand)]
    Transactions(TransactionsCmd),
    /// Asset transfers between brokerages (ACATS).
    #[command(subcommand)]
    Transfers(TransfersCmd),
    /// Dividend payments — the 1099-DIV raw material.
    #[command(subcommand)]
    Dividends(DividendsCmd),
    /// Cash-sweep interest payments — the 1099-INT raw material.
    #[command(subcommand)]
    Interest(InterestCmd),
    /// Net worth across the login's brokerage accounts (net-worth/v1).
    ///
    /// One figure per account — its own cash plus its verified stock/ETF
    /// holdings valued at last trade; Robinhood exposes no truthful
    /// per-account total endpoint (docs/api.md 3.8) — rolled up into a
    /// household total covering every active brokerage account in the
    /// login. Scope: cash + equities only (options and crypto are not yet
    /// valued); the DTO declares this in its `covers` field. An explicit
    /// -a/--account (or RHD_ACCOUNT) narrows it for this invocation;
    /// unlike other reads, a profile's persisted default account is
    /// deliberately ignored, so a configured default can never silently
    /// turn the household figure into one account's balance.
    NetWorth,
    /// Tax forms and statements (documents/v1 profile).
    #[command(subcommand)]
    Documents(DocumentsCmd),
    /// Raw read-only API passthrough (GET only).
    Api(ApiArgs),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
    /// Serve read-only Robinhood tools to Claude over MCP (stdio, or --http).
    ///
    /// For Claude Code (`claude mcp add robinhood -- rhd mcp`), Claude
    /// Desktop and any MCP client. With --http, on 127.0.0.1 behind a bearer
    /// token, for Claude on the web and mobile through your own Cloudflare
    /// Worker and tunnel. The tools use the selected profile's session from
    /// `rhd auth login --browser`, and never sign in themselves.
    Mcp(pk_cli_mcp::McpArgs),
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Sign in through a Chrome window with --browser; --session-stdin and
    /// the password login are the fallbacks.
    ///
    /// --browser opens https://robinhood.com/login in a Chrome profile rhd
    /// keeps for this login. You sign in there, and rhd takes the session the web app
    /// stores, closes the window, proves the session with one read of your
    /// accounts, and keeps it in the OS keychain (docs/api.md §2.8).
    ///
    /// Without Chrome, --session-stdin imports a session you copy out of
    /// DevTools in your own browser. With neither flag, rhd logs in with the
    /// password, which raises an in-app device approval that may never
    /// reach your phone (docs/api.md §6).
    Login(RhLoginArgs),
    /// Report credential/session state (auth-status/v1).
    Status(StatusArgs),
    /// Clear the session and remove the kept browser profile.
    ///
    /// --forget also removes stored credentials and this login's config entry.
    /// Every step is attempted even after one fails; then this says what is cleared
    /// and what remains, and exits with the first failure's code. While Chrome is
    /// using the kept profile that is exit 1, with the rest already cleared. The
    /// config entry goes last, only once the rest is clear, so a retry finds it.
    Logout(LogoutArgs),
    /// Raw keychain write for rotation / headless setup.
    SetCredential(SetCredentialArgs),
}

/// `auth login`: the family's `--browser` first (it is the way in), then
/// the password login's flags and the two things a challenge-gated provider
/// needs, then `--session-stdin`.
///
/// `--browser` is the shared `BrowserArgs` flag; `mut_arg` gives it this
/// CLI's long help and refuses every other credential source and every
/// password-login flag beside it at parse time (exit 2), before any config,
/// keychain or network work.
///
/// `--fresh-profile` needs the same list of its own. Its `requires = "browser"`
/// does not hold once one of these is present: clap counts a required argument
/// as satisfied when it conflicts with an argument given, so
/// `--session-stdin --fresh-profile` would parse and run the import.
#[derive(clap::Args, Debug)]
#[command(mut_arg("browser", |a| a
    .long_help(BROWSER_HELP)
    .conflicts_with_all([
        "session_stdin", "stdin", "from_env", "no_verify", "code", "resume", "username", "channel",
    ])))]
#[command(mut_arg("fresh_profile", |a| a
    .conflicts_with_all([
        "session_stdin", "stdin", "from_env", "no_verify", "code", "resume", "username", "channel",
    ])))]
struct RhLoginArgs {
    #[command(flatten)]
    browser: BrowserArgs,

    #[command(flatten)]
    base: LoginArgs,

    /// Robinhood username (an email address). Remembered in the profile.
    #[arg(long, value_name = "EMAIL")]
    username: Option<String>,

    /// Verification code, to resume a login that requested one.
    ///
    /// A challenge belongs to the login attempt that raised it, so this
    /// resumes the parked attempt rather than starting a fresh one.
    #[arg(long, value_name = "CODE")]
    code: Option<String>,

    /// Continue a parked login that needs no code — the case where Robinhood
    /// asked you to approve the device in its phone app.
    #[arg(long, conflicts_with = "code")]
    resume: bool,

    /// Where to send the verification code when a challenge is raised.
    #[arg(long, value_enum, default_value = "sms")]
    channel: client::Channel,

    /// Fallback for --browser: import a session copied out of a logged-in
    /// robinhood.com tab, read from stdin.
    #[arg(
        long,
        long_help = SESSION_STDIN_HELP,
        conflicts_with_all = ["code", "resume", "username", "channel", "stdin", "from_env", "no_verify"]
    )]
    session_stdin: bool,
}

/// `--browser`'s long help: what opens, what is read from where, and what
/// happens to the window. Verbatim, like [`SESSION_STDIN_HELP`].
const BROWSER_HELP: &str = "\
Sign in through a Chrome window and capture the session from it: the
password and any code are entered on Robinhood's own page, never in rhd.

rhd starts Chrome at https://robinhood.com/login in a profile it keeps for
this login, separate from every other login's. Sign in there, answering any
code or approval Robinhood asks for. Once the robinhood.com page holds a
session Robinhood accepts, rhd takes it from that page only
(localStorage['web:auth_state'], plus the device_id cookie) and closes
the tab at once, so the web app cannot renew the session out from under
rhd. Then it quits Chrome, reads your accounts once with the session, and
stores it in the OS keychain only if that read succeeds. It never prints
the token.

The kept profile lets Robinhood remember this device, so a later sign-in
often asks for less. It is a full Chrome profile, owner-only on disk:
Robinhood's cookies, the session's tokens, browsing history with full URLs,
the HTTP cache and site storage stay, after a failed sign-in too, until
`rhd auth logout` removes it. --fresh-profile signs in through a scratch
profile instead.

Waits up to 10 minutes; Ctrl-C cancels. Chrome, Chromium or Edge is found
at the standard install paths; set RHD_CHROME to use another binary.
Without Chrome, use --session-stdin.";

/// The `--session-stdin` walkthrough: the exact DevTools steps for each
/// shape. Kept verbatim (not a doc comment) so clap does not reflow the
/// snippet and the numbered steps. docs/api.md §2.8.
const SESSION_STDIN_HELP: &str = "\
The fallback for --browser: import a session from a logged-in
robinhood.com tab in your own browser, read from stdin. Use it when
Chrome is not installed or the --browser capture fails (docs/api.md §2.8).

Log in at https://robinhood.com in a desktop browser, open DevTools
(Chrome: View > Developer > Developer Tools), and capture ONE of:

1. The stored session. Renews itself; prefer this. In the Console tab, run
   (Chrome may first ask you to type `allow pasting`):

     copy(JSON.stringify({...JSON.parse(localStorage['web:auth_state']), device_token: (document.cookie.match(/(?:^|; )device_id=([^;]+)/) || [])[1]}))

   That copies the value stored at Application > Local Storage >
   https://robinhood.com > web:auth_state, plus the browser's device_id
   cookie, which renewal presents. Copying the web:auth_state value by hand
   from the Application tab also works, but leaves the device id out.

2. A bearer token. Cannot renew; lasts until it expires. In the Network
   tab, reload the page, click any request to api.robinhood.com, and under
   Headers > Request Headers copy the value of `authorization`
   (`Bearer ...`).

Then pipe the clipboard in (add --profile <NAME> for a non-default login):

  pbpaste | rhd auth login --session-stdin

rhd reads your accounts once with the session and stores it only if that
read succeeds; it never prints the token. Afterwards close the
robinhood.com tab, but do not click Log out: logging out revokes the
session rhd just stored.";

#[derive(clap::Args, Debug)]
struct StatusArgs {
    /// Spend a request confirming the cached session still works.
    #[arg(long)]
    verify: bool,
}

#[derive(Subcommand, Debug)]
enum ProfilesCmd {
    /// List configured login profiles (login-profile-list/v1).
    #[command(visible_alias = "ls")]
    List {
        /// Also report whether each profile has stored credentials.
        ///
        /// Opt-in: it reads two keychain entries per profile, which on macOS
        /// can raise a permission dialog for each.
        #[arg(long)]
        check: bool,
    },
    /// Add a login profile.
    Add {
        /// Profile name, e.g. `primary` or `spouse`.
        name: String,
        /// Robinhood username (an email address) for this login.
        #[arg(long, value_name = "EMAIL")]
        username: Option<String>,
        /// Default brokerage account number within this login.
        #[arg(long, value_name = "ID")]
        account: Option<String>,
    },
    /// Remove a login profile, its credentials and its kept browser profile.
    ///
    /// Every step is attempted even after one fails; then this says what is cleared
    /// and what remains, and exits with the first failure's code. The config entry
    /// goes last, only once the rest is clear, so a retry finds it.
    Remove {
        name: String,
        /// Remove without confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Make a profile the default for later commands.
    Use { name: String },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key (`default_profile`, or `<profile>.username`/`.account`).
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

#[derive(Subcommand, Debug)]
enum AccountsCmd {
    /// List every brokerage account in this login (account-list/v1).
    #[command(visible_alias = "ls")]
    List,
    /// Show one account; defaults to the selected account.
    Get { id: Option<String> },
}

#[derive(Subcommand, Debug)]
enum PositionsCmd {
    /// List holdings (position-list/v1).
    ///
    /// Takes --limit but not --since/--until: a holding has no single date to
    /// bound it by, and accepting a flag that quietly did nothing would be
    /// worse than not offering it.
    #[command(visible_alias = "ls")]
    List {
        /// Maximum records to return.
        #[arg(long, value_name = "N")]
        limit: Option<u32>,
        /// Include closed positions (zero quantity), not just current holdings.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        accounts: AllAccounts,
    },
}

/// `--all-accounts`, shared by every read that can fan out.
#[derive(clap::Args, Debug, Clone, Copy)]
struct AllAccounts {
    /// Read every brokerage account in the login, one scoped read each, and
    /// tag every row with its account_number and account_kind. Without it a
    /// read covers one account: the selected one, or for orders the login's
    /// default account. Conflicts with -a/--account (docs/api.md §3.14).
    #[arg(long)]
    all_accounts: bool,
}

#[derive(Subcommand, Debug)]
enum TransfersCmd {
    /// List ACATS transfers in and out, newest first (acats-transfer-list/v1).
    ///
    /// Each transfer names its Robinhood account, the other brokerage, its
    /// state and date, and its assets (shares by symbol, cash by currency).
    /// Robinhood reports no cost basis for transferred shares. --since and
    /// --until filter on the transfer's date (settlement, else request),
    /// client-side (docs/api.md §3.13).
    Acats {
        #[command(flatten)]
        range: RangeArgs,
    },
}

#[derive(Subcommand, Debug)]
enum OptionsCmd {
    /// List open option positions with mark prices (option-position-list/v1).
    ///
    /// One row per contract: underlying, call/put, strike, expiry,
    /// long/short, quantity, average open price, cost basis, mark, market
    /// value, and unrealized P/L. `cost_basis` is the clearing firm's FIFO
    /// remaining-lot figure; it differs from average x quantity once a
    /// position has been partly closed (docs/api.md §3.9). Short positions
    /// carry negative basis and market value, so P/L = market value - basis
    /// for both directions. Options orders (realized premium) are
    /// `transactions options`.
    #[command(visible_alias = "ls")]
    Positions {
        #[command(flatten)]
        accounts: AllAccounts,
    },
}

#[derive(Subcommand, Debug)]
enum TransactionsCmd {
    /// List settled equity orders in a date range (transaction-list/v1).
    ///
    /// Does NOT include options activity — the provider splits the two.
    /// See `transactions options`.
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
        /// Include per-fill detail (price, quantity, settlement date) on
        /// each order.
        #[arg(long)]
        executions: bool,
        #[command(flatten)]
        accounts: AllAccounts,
    },
    /// List options orders in a date range (option-order-list/v1).
    ///
    /// Legs carry side/effect/type/strike/expiry; `processed_premium` is
    /// signed by cash flow (credit +, debit -). Realized figures live on
    /// `filled` rows and on cancelled rows that executed part of
    /// themselves first; other cancelled and resting (`confirmed`) orders
    /// are empty, so gate on the executed quantity downstream (docs/api.md
    /// §3.4). A full-year pull on an options-heavy account pages at the
    /// polite request rate and can take minutes; narrow with
    /// --since/--until where a slice will do.
    Options {
        #[command(flatten)]
        range: RangeArgs,
        /// Include per-fill detail on each leg.
        #[arg(long)]
        executions: bool,
        #[command(flatten)]
        accounts: AllAccounts,
    },
    /// List option exercises, assignments and expirations
    /// (option-event-list/v1).
    ///
    /// The option activity neither order feed records: each event names
    /// its contract (underlying, call/put, strike, expiry), the contracts
    /// it closed, the shares it moved (received or delivered at the
    /// strike) and its cash, signed by cash flow (credit +, debit -). An
    /// assignment's cash is net of the sale's fees. Date and account
    /// filters apply client-side (docs/api.md §3.10).
    OptionEvents {
        #[command(flatten)]
        range: RangeArgs,
        #[command(flatten)]
        accounts: AllAccounts,
    },
}

#[derive(Subcommand, Debug)]
enum DividendsCmd {
    /// List dividend payments in a date range (dividend-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
    },
}

#[derive(Subcommand, Debug)]
enum InterestCmd {
    /// List cash-sweep interest payments in a date range (interest-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
    },
}

#[derive(Subcommand, Debug)]
enum DocumentsCmd {
    /// List published documents, newest first (document-list/v1).
    #[command(visible_alias = "ls")]
    List {
        #[command(flatten)]
        range: RangeArgs,
        /// Only this document type: `1099` (the consolidated 1099),
        /// `account_statement`, or `trade_confirm`.
        #[arg(long = "type", value_name = "TYPE")]
        kind: Option<String>,
    },
    /// Download a document to disk (document-download/v1).
    #[command(visible_alias = "get")]
    Download {
        /// Document id. Omit with --all.
        id: Option<String>,
        /// Write to this file, or directory when used with --all. `-` = stdout.
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Download every matching document into the output directory.
        /// Scoped by --type/--since/--until — without any of them this is
        /// every document the account has ever produced.
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        range: RangeArgs,
        /// Only this document type, e.g. `1099`. Applies to --all.
        #[arg(long = "type", value_name = "TYPE")]
        kind: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        std::process::exit(output::fail(&e, cli.common.json));
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    // Commands that need neither config, keychain, nor network are answered
    // first, so `--help`, `completions`, and `info` can never prompt or hang.
    match &cli.command {
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            return Ok(());
        }
        Command::Info => return commands::misc::info(cli.common.json),
        Command::Mcp(args) if args.list_tools => {
            // The definitions need no config, profile or session; building
            // a context reads nothing.
            let ctx =
                commands::Ctx::new(cli.common.clone(), Config::default(), String::new(), None)?;
            return pk_cli_mcp::run(
                args,
                mcp::RobinhoodTools::new(mcp::LiveSource::new(ctx), Ok(String::new())),
            );
        }
        Command::SelfUpdate(args) => {
            return Updater {
                repo: REPO.into(),
                binary: BIN.into(),
                target: env!("BUILD_TARGET").into(),
                current: env!("CARGO_PKG_VERSION").into(),
            }
            .run_noting(
                args,
                cli.common.json,
                cli.common.quiet,
                &pk_cli_mcp::restart_note(BIN),
            )
        }
        _ => {}
    }

    // Everything checkable without config, keychain, or network is checked
    // here, so bad input fails the same way whether or not the machine has
    // credentials — and never reaches the provider (SPEC v1 §1.2).
    validate(&cli.command)?;
    if all_accounts(&cli.command) && cli.account.is_some() {
        return Err(CliError::Usage(
            "--all-accounts reads every account; it cannot be combined with -a/--account \
             (or RHD_ACCOUNT)"
                .into(),
        ));
    }

    let store = ConfigStore::new(BIN).with_override(cli.config.clone());
    if let Command::Auth(AuthCmd::Logout(args)) = &cli.command {
        return auth_logout(cli, &store, args);
    }
    let cfg: Config = store.load()?;

    match &cli.command {
        Command::Config(cmd) => config_cmd(cli, cmd, &store, cfg),
        Command::Profiles(cmd) => profiles_cmd(cli, cmd, &store, cfg),
        Command::Auth(cmd) => auth_cmd(cli, cmd, &store, cfg),
        Command::Mcp(args) => {
            // The tools take an `account` argument, so -a/RHD_ACCOUNT is not
            // passed on. A profile that cannot be chosen fails each call
            // rather than the server's start.
            let profile = cfg.require_profile(cli.profile.as_deref());
            let name = profile.as_deref().unwrap_or_default().to_string();
            let ctx = commands::Ctx::new(cli.common.clone(), cfg, name, None)?;
            pk_cli_mcp::run(
                args,
                mcp::RobinhoodTools::new(mcp::LiveSource::new(ctx), profile),
            )
        }
        _ => {
            // Everything below reads the provider, so it needs a resolved
            // profile and a session.
            let profile = cfg.require_profile(cli.profile.as_deref())?;
            let ctx = commands::Ctx::new(cli.common.clone(), cfg, profile, cli.account.clone())?;
            match &cli.command {
                Command::Accounts(AccountsCmd::List) => commands::accounts::list(&ctx),
                Command::Accounts(AccountsCmd::Get { id }) => {
                    commands::accounts::get(&ctx, id.as_deref())
                }
                Command::Positions(PositionsCmd::List {
                    limit,
                    all,
                    accounts,
                }) => commands::positions::list(&ctx, *limit, *all, accounts.all_accounts),
                Command::Options(OptionsCmd::Positions { accounts }) => {
                    commands::options::positions(&ctx, accounts.all_accounts)
                }
                Command::Transactions(TransactionsCmd::List {
                    range,
                    executions,
                    accounts,
                }) => commands::transactions::list(&ctx, range, *executions, accounts.all_accounts),
                Command::Transactions(TransactionsCmd::Options {
                    range,
                    executions,
                    accounts,
                }) => commands::transactions::list_options(
                    &ctx,
                    range,
                    *executions,
                    accounts.all_accounts,
                ),
                Command::Transactions(TransactionsCmd::OptionEvents { range, accounts }) => {
                    commands::option_events::list(&ctx, range, accounts.all_accounts)
                }
                Command::Transfers(TransfersCmd::Acats { range }) => {
                    commands::transfers::acats(&ctx, range)
                }
                Command::Dividends(DividendsCmd::List { range }) => {
                    commands::dividends::list(&ctx, range)
                }
                Command::Interest(InterestCmd::List { range }) => {
                    commands::interest::list(&ctx, range)
                }
                // The explicit flag/env only — never the profile's persisted
                // default account, which must not narrow a household figure.
                Command::NetWorth => commands::networth::show(&ctx, cli.account.as_deref()),
                Command::Documents(DocumentsCmd::List { range, kind }) => {
                    commands::documents::list(&ctx, range, kind.as_deref())
                }
                Command::Documents(DocumentsCmd::Download {
                    id,
                    output,
                    all,
                    range,
                    kind,
                }) => commands::documents::download(
                    &ctx,
                    id.as_deref(),
                    output.as_deref(),
                    *all,
                    range,
                    kind.as_deref(),
                ),
                Command::Api(args) => commands::api::run(&ctx, args),
                // Handled above.
                Command::Auth(_)
                | Command::Profiles(_)
                | Command::Config(_)
                | Command::SelfUpdate(_)
                | Command::Completions { .. }
                | Command::Info
                | Command::Mcp(_) => unreachable!("dispatched before session setup"),
            }
        }
    }
}

/// Whether the command asked for `--all-accounts`.
fn all_accounts(command: &Command) -> bool {
    match command {
        Command::Positions(PositionsCmd::List { accounts, .. })
        | Command::Options(OptionsCmd::Positions { accounts })
        | Command::Transactions(
            TransactionsCmd::List { accounts, .. }
            | TransactionsCmd::Options { accounts, .. }
            | TransactionsCmd::OptionEvents { accounts, .. },
        ) => accounts.all_accounts,
        _ => false,
    }
}

/// Argument checks that need nothing but the arguments themselves.
///
/// Kept in one place, ahead of any config load, so `rhd transactions list
/// --since 06/30/2026` is a usage error on a machine that has never been
/// configured — rather than an "ambiguous profile" error that hides the real
/// mistake.
fn validate(command: &Command) -> Result<(), CliError> {
    match command {
        Command::Transactions(
            TransactionsCmd::List { range, .. }
            | TransactionsCmd::Options { range, .. }
            | TransactionsCmd::OptionEvents { range, .. },
        )
        | Command::Transfers(TransfersCmd::Acats { range })
        | Command::Dividends(DividendsCmd::List { range })
        | Command::Interest(InterestCmd::List { range }) => range.validate(),

        Command::Documents(DocumentsCmd::List { range, kind }) => {
            range.validate()?;
            match kind.as_deref() {
                Some(k) => commands::documents::validate_type(k),
                None => Ok(()),
            }
        }

        Command::Api(args) => {
            // Read-only is a safety property of this tool, so the refusal is a
            // usage error (exit 2), not a confirmation prompt (exit 6): there
            // is no --force that would make a write work, and reporting 6
            // would invite a caller to retry as though there were.
            let method = args.method.trim().to_uppercase();
            if method != "GET" {
                return Err(CliError::Usage(format!(
                    "`rhd api` is read-only and accepts GET only (got {method})"
                )));
            }
            Ok(())
        }

        Command::Documents(DocumentsCmd::Download {
            id,
            all,
            range,
            kind,
            ..
        }) => {
            range.validate()?;
            if let Some(k) = kind.as_deref() {
                commands::documents::validate_type(k)?;
            }
            match (id.is_some(), *all) {
                (true, true) => Err(CliError::Usage(
                    "pass either a document id or --all, not both".into(),
                )),
                (false, false) => Err(CliError::Usage(
                    "which document? pass an id, or --all with -o <DIR>".into(),
                )),
                // Filters only make sense for --all; with an id they would
                // quietly do nothing, which is worse than refusing.
                (true, false)
                    if range.since.is_some()
                        || range.until.is_some()
                        || range.limit.is_some()
                        || kind.is_some() =>
                {
                    Err(CliError::Usage(
                        "--type/--since/--until/--limit scope --all; a document id already names \
                         one document"
                            .into(),
                    ))
                }
                _ => Ok(()),
            }
        }

        _ => Ok(()),
    }
}

/// `auth logout`, which a config that cannot be parsed must not stop: every step
/// but the config entry needs only the login's name. Without `--profile` or
/// `$RHD_PROFILE` the name is in that file, and this does not guess: the default
/// name could log out the wrong login, or none, and say it had.
fn auth_logout(cli: &Cli, store: &ConfigStore, args: &LogoutArgs) -> Result<(), CliError> {
    let cfg: Result<Config, CliError> = store.load();
    let profile = match &cfg {
        Ok(cfg) => cfg.require_profile(cli.profile.as_deref())?,
        Err(e) => config::named_profile(cli.profile.as_deref()).ok_or_else(|| {
            CliError::Other(format!(
                "{e}. That file says which login to log out, so nothing is cleared yet: name it \
                 with `rhd auth logout --profile <NAME>`"
            ))
        })?,
    };
    commands::auth::logout(&cli.common, store, cfg, &profile, args.forget)
}

fn auth_cmd(cli: &Cli, cmd: &AuthCmd, store: &ConfigStore, cfg: Config) -> Result<(), CliError> {
    let profile = cfg.require_profile(cli.profile.as_deref())?;
    match cmd {
        AuthCmd::Login(args) if args.browser.browser => {
            let fresh_profile = args.browser.fresh_profile;
            commands::auth::browser_login(&cli.common, store, cfg, &profile, fresh_profile)
        }
        AuthCmd::Login(args) if args.session_stdin => commands::auth::import_session(
            &cli.common,
            store,
            cfg,
            &profile,
            args.base.non_interactive,
        ),
        AuthCmd::Login(args) => commands::auth::login(
            &cli.common,
            store,
            cfg,
            &profile,
            &commands::auth::LoginInput {
                base: &args.base,
                username: args.username.as_deref(),
                code: args.code.as_deref(),
                resume: args.resume,
                channel: args.channel,
            },
        ),
        AuthCmd::Status(args) => commands::auth::status(
            &cli.common,
            &cfg,
            &profile,
            cli.account.as_deref(),
            args.verify,
        ),
        AuthCmd::Logout(_) => unreachable!("served before the config is loaded"),
        AuthCmd::SetCredential(args) => {
            commands::auth::set_credential(&cli.common, store, cfg, &profile, args)
        }
    }
}

fn profiles_cmd(
    cli: &Cli,
    cmd: &ProfilesCmd,
    store: &ConfigStore,
    cfg: Config,
) -> Result<(), CliError> {
    match cmd {
        ProfilesCmd::List { check } => commands::profiles::list(&cli.common, &cfg, *check),
        ProfilesCmd::Add {
            name,
            username,
            account,
        } => commands::profiles::add(
            &cli.common,
            store,
            cfg,
            name,
            username.as_deref(),
            account.as_deref(),
        ),
        ProfilesCmd::Remove { name, force } => {
            commands::profiles::remove(&cli.common, store, cfg, name, *force)
        }
        ProfilesCmd::Use { name } => commands::profiles::use_profile(&cli.common, store, cfg, name),
    }
}

fn config_cmd(
    cli: &Cli,
    cmd: &ConfigCmd,
    store: &ConfigStore,
    cfg: Config,
) -> Result<(), CliError> {
    commands::misc::config(&cli.common, store, cfg, cmd_to_config_op(cmd))
}

/// Translate the clap enum into the command module's own operation type, so
/// `commands::misc` doesn't depend on the clap tree.
fn cmd_to_config_op(cmd: &ConfigCmd) -> commands::misc::ConfigOp<'_> {
    match cmd {
        ConfigCmd::Path => commands::misc::ConfigOp::Path,
        ConfigCmd::Show => commands::misc::ConfigOp::Show,
        ConfigCmd::Set { key, value } => commands::misc::ConfigOp::Set(key, value),
        ConfigCmd::Unset { key } => commands::misc::ConfigOp::Unset(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// clap's own debug assertions catch conflicting shorts (e.g. a
    /// subcommand `-a` shadowing the global `--account`) only when the command
    /// tree is built, so build it.
    #[test]
    fn command_tree_is_valid() {
        Cli::command().debug_assert();
    }
}
