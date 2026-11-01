//! `rhd api GET <PATH>` — raw read-only passthrough.
//!
//! Useful for exploring shapes this CLI doesn't model yet, and for capturing a
//! response to turn into a fixture. GET only: see `main::validate`, which
//! refuses write verbs before the keychain or the network is touched.

use pk_cli_core::{output, CliError};
use pk_cli_http::ApiArgs;

use crate::commands::Ctx;

pub fn run(ctx: &Ctx, args: &ApiArgs) -> Result<(), CliError> {
    // The verb was already checked in `main::validate`; assert the invariant
    // here too so this stays true if it ever gains another caller.
    debug_assert_eq!(args.method.trim().to_uppercase(), "GET");

    let token = ctx.access_token()?;
    let url = args.url(ctx.rh.base());
    let v = ctx.rh.get(&token, &url, &[])?;
    output::json(&v);
    Ok(())
}
