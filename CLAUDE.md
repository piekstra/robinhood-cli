# CLAUDE.md

The canonical agent guide for this repo is **[AGENTS.md](AGENTS.md)** — read it
first. It covers build/test/lint, layout, conventions, and the safety rules.

Claude Code specifics:

- **Gate on `make verify`.** Don't report a change as done until it's green
  (fmt + clippy `-D warnings` + tests + smoke). Tests are fully offline.
- **This CLI is read-only, and that is a safety property.** It reads real
  brokerage accounts. Never add order entry, transfers, or settings changes;
  `rhd api` is GET-only by design.
- **Secrets:** password, OAuth access/refresh tokens, device token, and any
  parked mid-challenge login live in the OS keychain (`piekstra.rhd`,
  namespaced per login profile). Never print one, put it on argv, or write it
  to a file — including while debugging.
- **A live login costs the owner a phone interaction** and risks a device
  challenge or lockout. There is no retry loop anywhere in the auth path, on
  purpose. Prefer the offline fixtures; **ask before spending a live login.**
  When the approval prompt never reaches the phone, the owner's way in is a
  browser sign-in, `rhd auth login --browser` (docs/api.md §2.8), with
  `--session-stdin` as its fallback — never a retried password login.
  `--browser` opens a Chrome window and waits for the owner to sign in: never
  run it unattended or from a test.
- **Unofficial API.** Robinhood publishes no public retail API, so treat
  `docs/api.md` as a best-effort model, not a contract. Anything marked
  **UNVERIFIED-LIVE** has never been confirmed against the real service — do
  not describe it as working.
- **Never claim success without positive confirmation.** 200-with-HTML is an
  auth failure; a "downloaded" file that doesn't start with `%PDF` is not a
  document.
- **Written as if public.** No real account numbers, balances, positions,
  names, or emails in any diff — including test fixtures (dummies only).
