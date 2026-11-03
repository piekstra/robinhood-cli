# The Robinhood API, as `rhd` uses it

Robinhood publishes **no public retail API**. Everything below is community
reverse-engineering, cross-checked across three independent clients and dated
**2026-08-12**. It can break without notice, and the auth flow in particular
has been reshaped several times since late 2024.

On **2026-08-12** this project ran its first live session against a real
account (one login profile, four brokerage accounts): login with the
device-approval workflow, accounts, positions, orders, documents, and a real
consolidated-1099 download were all exercised. §6 records exactly what that
session proved and what it disproved.

On **2026-10-27** the password login stopped being usable for the owner: every
attempt raised a device-approval prompt that never reached the phone (§6). The
way in since then is a browser sign-in: `rhd auth login --browser` opens Chrome
at robinhood.com, the owner signs in on Robinhood's own page, and `rhd` reads
the session the web app stores (§2.8). Its fallback, `rhd auth login
--session-stdin`, imports the same session copied out of DevTools. Claims are
labelled:

- **LIVE-VERIFIED (this project)** — confirmed against a real account by this
  CLI, with the date.
- **LIVE-VERIFIED (community)** — a community maintainer states they confirmed
  it against the real service.
- **PROVIDER CODE** — read from the robinhood.com web app's own JavaScript
  bundle (public, no login needed), with the date. It says what the web app
  does, not that `rhd` has done it against the live service.
- **WELL-ATTESTED** — the same shape appears in ≥2 independent community
  clients, or in a captured trace.
- **UNVERIFIED** — plausible, single-sourced, or inferred. Treat as a guess.

Primary sources, newest first:

| Source | What it is |
| --- | --- |
| robinhood.com web bundle | The web app's public JavaScript, read 2026-10-27 for how it stores and renews its session (§2.8) |
| [robinhood-for-agents](https://github.com/kevin1chun/robinhood-for-agents) | TypeScript client that captures a browser login's tokens and renews them outside the browser (2026) |
| [rhood-rs](https://github.com/seferino-fernandez/rhood-rs) | Rust client, typed models, some live-verified notes (2026) |
| [pyhood](https://github.com/jamestford/pyhood) | Python client with token refresh + rate-limit docs (2026) |
| [robin_stocks](https://github.com/jmfernandes/robin_stocks) | The canonical community auth implementation |
| [robinhood-decompiled](https://github.com/ScriptedAlchemy/robinhood-decompiled) | Decompiled Android app — authoritative for enums |
| [sanko/Robinhood](https://github.com/sanko/Robinhood) | The classic docs — **2016-era, auth section obsolete** |

---

## 1. Headline findings

Four things shape this CLI more than anything else.

**1.1 — There is no realized-gain endpoint, and no unified transaction
ledger.** The community reconstructs cost basis by walking filled orders
(robin_stocks' `export.py` does exactly this). So `rhd transactions list`
surfaces **orders**, which are the raw material for Form 8949 — not a computed
gain. The provider also splits that raw material in two: equities `/orders/`
carries **no options activity**, which lives at `/options/orders/`
(`rhd transactions options`, §3.4.1 — LIVE-VERIFIED 2026-08-24), and
exercises, assignments and expirations are in neither order feed — they
live at `/options/events/` (`rhd transactions option-events`, §3.10). Only
`filled` rows carry realized figures — `cancelled` and `confirmed` (resting)
rows are legitimately empty, so consumers filter on state (§3.4). For actual
tax figures the consolidated 1099 is the source of truth. Any tool that
presents order history as "realized gains" is wrong wherever wash sales,
corporate actions, options assignment, or transferred-in lots are involved.
Transferred-in lots arrive with no order and no basis (`rhd transfers
acats`, §3.13). And every one of these feeds answers for **one account at a
time** — an unscoped order read is the login's default account only (§3.4)
— so a household's complete history needs `--all-accounts` (§3.14).

**1.2 — The tax documents endpoint exists, the 1099 filter is `1099`, and a
season's consolidated 1099 ships as a PDF *and* a CSV.** `GET
/documents/?type=1099` is **LIVE-VERIFIED (this project, 2026-08-12)** — 18
results on a real account, and a real consolidated-1099 PDF downloaded with
its `%PDF` magic confirmed. The natural guess `tax_1099` returns HTTP 400
(community-verified); `rhd` rejects it locally with the right answer. The live
capture also surfaced a field no community source documents: every document
carries a **`filetype`** (`pdf` | `csv` | `html`), and each tax season's
consolidated 1099 appears twice — the PDF form and a machine-readable CSV
export created days-to-weeks later. See §3.5.

**1.3 — A browser-like User-Agent gets you blocked, and the block looks
exactly like a wrong password.** Sending browser-shaped headers over a
non-Chrome TLS stack is flagged as impersonation, and Robinhood answers `400
{"detail":"Unable to log in with provided credentials."}` — the *same* body as
a genuinely bad credential. The community convention is the literal UA `*`.
`rhd` sends `*`, and its error message for that body names **both** possible
causes rather than asserting "wrong password" and sending you to rotate a
working credential.

**1.4 — Third-party TOTP no longer reliably works; phone approval dominates.**
Since late 2024 the "sheriff"/SUV device-approval workflow is what most logins
hit, and through 2025-2026 Robinhood increasingly forces an in-app "Yes, it's
me" tap that has no web equivalent. Plan for a human with a phone, not for an
unattended secret. This is why `rhd` distinguishes a *code* challenge from a
*prompt* challenge and offers `--resume` for the latter. And because the
prompt can fail to reach the phone at all (live 2026-08-12 and, on every
attempt, 2026-10-27), `rhd` signs in through a browser instead (`auth login
--browser`, §2.8).

---

## 2. Authentication

### 2.1 The token endpoint

`POST https://api.robinhood.com/oauth2/token/`, **form-urlencoded** (not JSON).
WELL-ATTESTED — byte-identical across robin_stocks, pyhood, and rhood-rs.

| Field | Value |
| --- | --- |
| `client_id` | `c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS` |
| `grant_type` | `password` |
| `scope` | `internal` |
| `expires_in` | `86400` |
| `username` / `password` | the credential |
| `device_token` | see §2.2 |
| `challenge_type` | `sms` or `email` |
| `try_passkeys` | `false` |
| `token_request_path` | `/login` |
| `create_read_only_secondary_token` | `true` |

The `client_id` identifies the *app*, not the user — it is public, hardcoded in
every community client, and is not a secret.

`expires_in` is **ignored by the server**. Observed access-token lifetimes are
~5-8 days, not 24 hours (pyhood's `authentication.md`; **LIVE-VERIFIED (this
project, 2026-08-12)** — the returned expiry was ~6 days out). `rhd` therefore
records an absolute expiry computed from whatever `expires_in` comes *back*,
and treats an unknown expiry as "still good" — the server stays the authority.

### 2.2 The device token buys device trust

Robinhood's clients build it from 16 random bytes hyphenated 8-4-4-4-12 — UUID
*shape* without the version/variant bits. `rhd` mints a v4 UUID, which is the
same shape, **once per profile**, then persists it in the keychain forever.

The community claim is that reusing the token stops later logins from
re-raising the device-approval challenge. **Live experience is worse than the
claim (this project, 2026-08-12):** a second password login ~30 minutes after
an approved first login, sending the *same* persisted `device_token` (reuse
verified in code), still raised a sheriff `prompt` workflow — and that prompt
**never surfaced** in the phone app (no push, no in-app card) and never
validated within the poll window. The working session from the first login
survived unharmed, because `rhd` only replaces the stored token bundle on
success. **On 2026-10-27 it happened on every attempt** (§6): the password
login was unusable, and the way back in was a browser session (§2.8).

Operational conclusions: persist and reuse the token anyway (regenerating is
indistinguishable, from Robinhood's side, from a brand-new device and strictly
worse); treat `auth login` as an owner-present operation that may re-challenge
every time; rely on **token refresh** (§2.5) — not repeated logins — for
anything unattended; and when the challenge never surfaces, sign in through
the browser (§2.8) rather than retrying.

### 2.3 The device-approval ("sheriff"/SUV) workflow — the dominant path

Triggered when the token response carries
`{"verification_workflow": {"id": "...", "workflow_status":
"workflow_status_internal_pending"}}`. **LIVE-VERIFIED (this project,
2026-08-12)** — the full sequence below, with a `prompt` challenge approved on
the owner's phone, completed a real login (including the non-TTY park →
`--resume` path).

1. `POST /pathfinder/user_machine/`
   → `{"device_id": <device_token>, "flow": "suv", "input": {"workflow_id": <id>}}`
   → responds `{"id": "<machine_id>"}`
2. `GET /pathfinder/inquiries/{machine_id}/user_view/` — read the challenge.
3. Then, by challenge type:
   - `prompt` / `app` → poll `GET /push/{challenge_id}/get_prompts_status/`
     until `{"challenge_status": "validated"}`
   - `sms` / `email` → `POST /challenge/{challenge_id}/respond/` with
     `{"response": "<code>"}`; success carries `status == "validated"`
4. `POST /pathfinder/inquiries/{machine_id}/user_view/`
   → `{"sequence": 0, "user_input": {"status": "continue"}}`
   → look for `type_context.result == "workflow_status_approved"`
5. Re-POST `/oauth2/token/` with the original body.

**Trap — the challenge object is duplicated at two paths.** Real captures carry
it at *both* `context.sheriff_challenge` and
`type_context.context.sheriff_challenge`, and different community clients read
different ones. `rhd` looks in both (`client::sheriff_challenge`), and the
fixture asserts both are present and equal.

**Trap — `prompt` and `app` mean "tap your phone", not "type a code".**
Misclassifying them leaves the user waiting for an SMS that never arrives.

### 2.4 The legacy `challenge` object

Older shape, still in community code: a 400 carrying `{"detail": "Request
blocked, prompt challenge issued.", "challenge": {"id", "type",
"alternate_type", "status", "remaining_attempts", ...}}`, answered at
`/challenge/{id}/respond/` and then re-presented via the
`X-ROBINHOOD-CHALLENGE-RESPONSE-ID` header. `rhd` still handles it; it is
increasingly rare.

### 2.5 Refresh is the only unattended path

```
grant_type=refresh_token & refresh_token=… & scope=internal
& client_id=… & device_token=… & expires_in=86400
```

**Refresh does not raise a device challenge** — which is exactly why it is the
one part of the flow `rhd` performs implicitly (in `Ctx::access_token`). Refresh
tokens **rotate on every use**, so the new one must be written back. If a
refresh response comes back carrying a `verification_workflow`, the refresh
token itself is dead and a full login is required; `rhd` reports that as an auth
error naming `rhd auth login --browser`.

Every `rhd` process shares that token: the long-running `mcp --http` server, a
stdio server and a terminal command read one keychain item. So a renewal runs
under an exclusive lock on `~/.config/rhd/token-refresh.lock` (an empty file;
`pk_cli_auth::refresh_lock`, whatever `--config` or `XDG_CONFIG_HOME` say). It
reads the session again once it holds the lock, and if the session is no longer
expired another process has renewed: it posts no grant and uses that process's
tokens. A wait is bounded at 75 s, then exit 5 naming the lock, with nothing
sent. All profiles share the one lock. It only excludes copies that take it, so the
protection starts once every copy is 0.4.2 or later, including a server not yet
restarted and an installed Claude Desktop extension, which bundles its own binary.

The `device_token` sent is the one the session was issued to. For a password
session that is the profile's `<profile>/device`; for a session from a browser
(§2.8) it is the browser's `device_id`, kept inside the token bundle — or
nothing, if the capture carried none. An imported session never presents the
profile's device token. A renewal response carries neither the origin nor the
device, so `rhd` copies both onto the renewed bundle.

### 2.6 Headers

WELL-ATTESTED, identical in robin_stocks and pyhood:

```
Accept: */*
Accept-Language: en-US,en;q=1
X-Robinhood-API-Version: 1.431.4
User-Agent: *
Content-Type: application/x-www-form-urlencoded; charset=utf-8   (token endpoint)
Authorization: Bearer <access_token>                              (after login)
```

See §1.3 on why the UA is `*` and not something browser-shaped. This is the one
place `rhd` deliberately overrides `pk_cli_http`'s family default, which would
otherwise send `rhd/<version>`.

### 2.7 Token response

`access_token`, `token_type` (`Bearer`), `refresh_token`, `expires_in`, `scope`,
`user_uuid`, `mfa_code` (null), `backup_code` (null). The community record
adds `read_only_secondary_access_token` when the login body sets
`create_read_only_secondary_token` — but **the live login of 2026-08-12
returned no such field** (sheriff-workflow path, flag sent; the stored bundle
was probed on 2026-08-13 and carries no read-only token). Either the provider
has stopped minting it, or it is conditional on something the community record
doesn't capture.

The web app is one thing it is conditional on, or at least not withheld from:
**PROVIDER CODE (2026-10-27)** — robinhood.com counts a token response as a
successful login only when it carries `access_token`, no `mfa_required`,
**and** `read_only_secondary_access_token`, and it sends
`create_read_only_secondary_token: true` on renewals too. So a session
imported from the browser (§2.8) should carry the read-only token.

`rhd` still parses and stores the field (an import keeps it too); nothing
uses it. See §7.

### 2.8 Browser sign-in — `auth login --browser`, and `--session-stdin`

**Why it exists.** Live on 2026-10-27, owner present: every password login
raised the sheriff `prompt` workflow (§2.3), including with `--channel email`
— the workflow chose `prompt` whatever `challenge_type` asked for — and the
approval request never surfaced in the phone app. Reinstalling the app,
signing in to it and restarting it changed nothing, and a `--resume` poll (12
× 10 s, §4.2) timed out with no prompt shown. That is the 2026-08-12
re-challenge failure (§2.2), now on every attempt. The same owner could log in
at robinhood.com in a desktop browser. So `rhd` imports the browser's session
instead of minting its own, and never retries the password login (§4.2).

**What the web app keeps — PROVIDER CODE (2026-10-27).** Read from the public
robinhood.com bundle, which needs no login to fetch:

| Fact | Detail |
| --- | --- |
| `localStorage['web:auth_state']` | The `/oauth2/token/` response as JSON. The web app's reader (`AuthPersistence_getAuthStateFromStorage`) takes exactly `access_token`, `refresh_token`, `expires_in`, `token_type`, `scope`, `read_only_secondary_access_token`, `user_uuid`, `mfa_code`, `backup_code` — §2.7's key set. Rewritten on every login and renewal. No device token |
| `client_id` | The web's production client id is `c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS` — the one `rhd` and every community client send (§2.1). A web-issued refresh token is therefore renewed with the client id `rhd` already uses, and nothing extra is stored |
| Device token | The web presents its `device_id` cookie as `device_token`: a v4 UUID it mints and sets for 10 years on the robinhood.com domain, from JavaScript (so `document.cookie` can read it) |
| Renewal | `grant_type: refresh_token` with `refresh_token`, `scope`, `device_token`, `client_id`, `create_read_only_secondary_token: true` and `token_request_path`, posted as JSON — §2.5's grant. A `web:refresh_token_lock` key serializes renewals across tabs |
| Access token | A JWT; the web reads the token's expiry from its `exp` claim |
| `__Host-Web-App-Secondary-Access-Token` cookie | Holds the **read-only secondary** token, not the primary one. Some community READMEs point at this cookie as "the access token" |
| Log out | Posts the access token to `/oauth2/revoke_token/` |

**`--browser`: what the capture reads, and from where.** `rhd` adopts the
family's `pk-cli-browser` (cli-common, DESIGN.md §2.2). It starts Chrome in a
profile `rhd` keeps for this login, the owner signs in on Robinhood's own page
(password and any code or approval happen there, never in `rhd`), and the
session is read over the Chrome DevTools Protocol:

| | |
| --- | --- |
| Launch | `https://robinhood.com/login` in a plain Chrome: a debug port Chrome picks, the kept `--user-data-dir` for this login (below; `--fresh-profile` uses a scratch one, created `0700` under an unpredictable name), first-run suppression, and no automation flags. Chrome, Chromium or Edge at the standard install paths; `RHD_CHROME` names another binary |
| Host | exactly `robinhood.com` (`HostRule::exact`): an `https` page on the default port whose parsed host is `robinhood.com`, and an answering document whose own `location.hostname` is too. Pages on `api.robinhood.com`, `www.robinhood.com` or a look-alike are never evaluated or closed. The login page is on the same host, so the check also runs there while the owner signs in; it reads `localStorage` and `document.cookie`, changes nothing, and answers `null` until signed in |
| Expression | polled every few seconds in those pages (below). `null` until `localStorage['web:auth_state']` parses (a double-encoded value too) and holds a non-empty `access_token`, so the tab is never closed on a half-written session; then it removes that entry and answers with the session as JSON, with the `device_id` cookie added as `device_token`, or `device_token: null` when `document.cookie` cannot see it |
| Cookie | `device_id`, as the browser would send it to `https://robinhood.com/`, read from the browser's cookie jar (`Storage.getCookies`, which includes `HttpOnly` cookies). Optional: the capture never waits on it. When the expression's `device_token` is null, `rhd` fills it from this cookie before parsing |
| Confirm | the hook takes the session only if it parses, is not past the point `rhd` would renew it (a minute before expiry) and Robinhood answers one read of `/accounts/` with its accounts list. A read that cannot decide (a throttle, Robinhood down) ends the wait; otherwise the tab stays open and the wait goes on (below) |
| Then | every robinhood.com tab is closed the instant the session is confirmed, and Chrome is stopped. The value goes to the same parser as `--session-stdin`, the same proving read and the same keychain item, so the two paths store identical credentials. `session-import/v1` reports `source: "browser"` |
| Wait | up to 10 minutes; status lines on stderr (`-q` silences them); Ctrl-C cancels. A timeout or a window closed before sign-in is exit 3 naming `rhd auth login --browser --profile <NAME>`; no Chrome is exit 1 pointing at `--session-stdin`. Every failure once Chrome has run in the kept profile adds that the profile stays and what removes it, whichever step failed (`commands::auth::through_the_window`) |

```js
(() => { const raw = localStorage['web:auth_state']; if (!raw) return null; let s; try { s = JSON.parse(raw); if (typeof s === 'string') s = JSON.parse(s); } catch { return null; } if (!s || !s.access_token) return null; const d = (document.cookie.match(/(?:^|; )device_id=([^;]+)/) || [])[1]; return JSON.stringify({ ...s, device_token: d || null }); })()
```

A browser session `rhd` cannot read (a `token_type` other than `Bearer`, a
`device_id` that is not a UUID) is exit 5, not a usage error: it is what
Robinhood's web app stored, and signing in again would not change it.

**Why the tab is closed at once.** Robinhood's site logout revokes the
session (it posts the access token to `/oauth2/revoke_token/`), and refresh
tokens rotate on every use (§2.5). After a capture, the web app and `rhd`
hold the same refresh token, and whichever renews first invalidates the
other's copy. The crate closes the tab before anything else happens, so the
web app can neither renew (and so rotate) the token `rhd` just took nor log
it out. That close-on-capture is what keeps `rhd`'s copy valid, and it is why
the `--session-stdin` traps below do not apply to `--browser`.

**The kept profile.** Chrome runs in
`~/Library/Application Support/piekstra.rhd/browser-profile-<NAME>` on macOS and
under `$XDG_DATA_HOME` (or `~/.local/share`) on Linux, owner-only (`0700`), one per
login profile (`Launch::profile_name`), so one household account's sign-in never
opens signed in as another. It stays when the window closes, after a failed sign-in
too. Its `device_id` cookie carries over (the web sets it for 10 years), so a later
sign-in presents a device Robinhood has seen. `--fresh-profile` uses a scratch
profile for one run instead. `auth logout` and `profiles remove` remove that login's
as their browser step, and name refusals (a sign-in or a Chrome using it, a symlink,
another user's) as exit 1, saying what is already cleared and how to finish. Chrome
is asked to quit over its debug port, so a cookie Robinhood sets just before the close
reaches the disk; cli-common measured that in headless Chrome, not in a visible
window. SECURITY.md lists what the profile holds.

`auth status` reports on the login it resolves to, as `browser_profile`: whether a
profile is kept for it, not whether anything is signed in there. A name a Chrome
profile cannot carry reports `false`, and a path that needs repair leaves the field
out with a warning.

A name a Chrome profile cannot carry (anything but 1 to 64 ASCII letters, digits,
`-` or `_`) is checked and never rewritten, so it can never land on another login's
profile. `rhd profiles add` already refused all but an over-long one, but
`--profile` or `RHD_PROFILE` on a fresh install can name any. `--browser` refuses
it, exit 2, before Chrome starts; `--browser --fresh-profile` signs it in, since a
scratch profile needs no name; and its logout finishes, since it never had a
profile to remove.

**The tokens do not stay.** A `web:auth_state` left in the profile would start the
next window on an access token that has often expired and a refresh token `rhd` has
rotated away, and the web app could present it, which at best signs it out and at
worst ends the session `rhd` holds. So the launch sets `clear_site_storage(true)`,
which keeps the cookies and removes `Default/Local Storage`, `Session Storage`,
`IndexedDB` and the rest of the site storage twice: before Chrome starts, where a
failure refuses the launch (exit 1, no Chrome), and again once Chrome has stopped. A
crash or a second Ctrl-C skips the second removal, as does a Chrome still running in
the profile; the tokens then stay on disk, `0700` their only protection, until the
next launch or logout. Each window therefore opens with no session in the page. The
expression only reads: the evaluation can run more than once, so a removal could lose
a session the capture never took.

**The confirm hook judges what it read.** The tab stays open on a session that does
not parse, is past the point `rhd` would renew it, or that Robinhood refuses, until a
new sign-in replaces it. `rhd` renews a minute before expiry, so the hook goes by the
renewal rule (`Tokens::is_expired_at`), not the bare expiry, and a session is never
stored already due for renewal. A refused token is remembered for the run and not sent
again, so a tab on a dead session costs one read rather than one per poll. A read that
cannot decide ends the wait with an error and takes nothing: a 429 or a 5xx whatever
its body, or a success that is not the accounts list. An HTML page on any other status
counts as a refusal; the tab stays open and that token is not sent again. `rhd` itself
never renews from the window.

A confirmed capture is read twice: once by the hook, to decide whether the tab
closes, and once after it, to decide whether anything is stored.

**A known device after the first sign-in — UNVERIFIED-LIVE.** A kept profile
starts with no cookies only the first time, so that first `--browser` sign-in (and
every `--fresh-profile` one) presents a new `device_id` (§2.2). Robinhood may ask
for a code or an approval on its page for that, and the owner answers it there.
Whether a web sign-in from a new device raises the same in-app approval that never
reaches the owner's phone (§6) is not known yet; if it does, `--session-stdin` from
the owner's everyday browser, which Robinhood already knows, is the way in. Whether
a later sign-in from the kept `device_id` skips the code is not known yet either.

**`--session-stdin`: the fallback.** For a machine without Chrome, or when
the `--browser` capture fails, the owner copies the session out of DevTools
in their own browser and pipes it in. It reads two shapes, told apart by the
first character:

1. **`web:auth_state`** (`{…}`) — preferred: it carries the refresh token, so
   `rhd` renews unattended. The `--help` Console snippet copies the value with
   the `device_id` cookie added as `device_token`:

   ```js
   copy(JSON.stringify({...JSON.parse(localStorage['web:auth_state']), device_token: (document.cookie.match(/(?:^|; )device_id=([^;]+)/) || [])[1]}))
   ```

   Copying the value by hand from DevTools → Application → Local Storage →
   `https://robinhood.com` → `web:auth_state` also works, without the device
   id. The value double-encoded (a JSON string) and a whole `copy(localStorage)`
   dump are accepted too.
2. **A bearer token** — the `authorization` request header of any
   api.robinhood.com request (DevTools → Network → a request → Headers →
   Request Headers). `Bearer …`, the header line, a "Copy as cURL" paste and the
   bare token are all accepted. No refresh token: the session ends when the
   token does. This is the capture community tools document (rh-trade-exporter,
   2026).

**Stored exactly where a password login stores its bundle** (`<profile>/token`),
so every command and renewal (§2.5) work unchanged, whichever path brought
it. The bundle gains two fields: `origin` (`web_auth_state` or `bearer`;
absent means a password session; `--browser` always stores `web_auth_state`)
and `device_token` (the browser's device id). The profile's own
`<profile>/device` is left untouched for the password login. `auth status`
reports `method: browser-session` for both paths, and `info` reports the same
method with `rhd auth login --browser` as its login hint.

**Proved before storing, with one read.** `GET /accounts/` with §3.2's
all-accounts query, using the captured token. On any failure nothing is stored
and the error says where the session came from and which shape it was read
as. A token whose `exp` has already passed is refused before the request (it
could only 401): for a paste, reloading robinhood.com renews the web's
session, then capture again; for `--browser`, a token that is expired the
moment it is captured means a wrong clock. The expiry comes from the JWT `exp`
claim; `expires_in` is not used, because the capture does not say when that
lifetime started. `--json` reports the import as `session-import/v1` (source,
shape, accounts visible, whether it renews, expiry, whether a device id and a
read-only token came with it) — never a token.

**Traps of `--session-stdin`** (the owner's own tab stays open, so the
close-on-capture above does not protect the copy):

- **Do not click Log out in the browser afterwards.** Logout revokes the access
  token `rhd` now holds. Close the tab instead.
- **One refresh chain, two holders.** Refresh tokens rotate on every use
  (§2.5), and after an import the browser and `rhd` hold the same one.
  Whichever renews first invalidates the other's copy. If the site renews
  first (it was open when its token neared expiry), `rhd`'s next renewal fails
  with an auth error that names `rhd auth login --browser`: sign in again. If
  `rhd` renews first, the browser's session ends and the site asks for a
  login.
- **Chrome guards its Console against pasted code**: it asks you to type
  `allow pasting` first. The snippet reads `localStorage` and
  `document.cookie` and copies to the clipboard; it sends nothing anywhere.

**UNVERIFIED-LIVE** — neither `--browser` nor a live paste has been run yet:

- that robinhood.com's sign-in completes in a kept-profile Chrome launched with
  a debug port, what a new device costs there, and what a known one saves (above);
- whether a visible window's quit gets a fresh cookie to the disk (above);
- that the `device_id` cookie is set by then, and whether `document.cookie`
  sees it (the bundle sets it from JavaScript; the jar read covers an
  `HttpOnly` one either way);
- that `web:auth_state` holds the session on the owner's browser (the key and
  its reader are in the shipped bundle; a live import is the proof);
- that a web-issued access token reads `/accounts/` from `rhd`, which sends UA
  `*` over a non-browser TLS stack (§1.3);
- that a web-issued refresh token renews from `rhd`. Single-sourced:
  robinhood-for-agents (2026) captures a browser login's tokens and renews
  them outside the browser with this client id and the web's `device_token`;
- renewal of an import that carried no device id (it presents no
  `device_token`);
- the bearer token's lifetime. rh-trade-exporter reports ~24 hours; the JWT's
  `exp` decides, and the import reports it.

---

## 3. Endpoints

Base `https://api.robinhood.com`; trailing slashes are significant.

### 3.1 Pagination

`{"next": <url|null>, "previous": <url|null>, "results": [...]}`.
**LIVE-VERIFIED (this project, 2026-08-12)** — a 1,268-document listing paged
cleanly. `next` is a **full URL** and must be followed verbatim — the cursor is
opaque and rebuilding the request drops fields. Community sources say default
page size ~100; `/documents/` served **500 rows per page** live. `rhd` caps the
chain at 200 pages so a read can't turn into thousands of requests, and
refuses a `next` that leaves the API origin — provider-supplied links are
dereferenced with the bearer token attached, so following one off-host would
hand the session token to whatever host the payload named
(`Rh::same_origin`).

### 3.2 Accounts — `GET /accounts/`

**`?default_to_all_accounts=true` is required for multi-account.** Without it
the endpoint returns the login's default account only, so a household member's
IRA or joint account silently never appears. This is the most consequential
query parameter in the CLI (`accounts::all_accounts_query`). **LIVE-VERIFIED
(this project, 2026-08-12):** all four brokerage accounts under one login
appeared — the owner confirmed the count.

**It is not enough: `include_managed=true` and
`include_multiple_individual=true` are required too.** Robinhood lets a
login hold a managed "Strategies" account and up to ten self-directed
individual accounts; both kinds stay **hidden** from
`?default_to_all_accounts=true` alone. **LIVE-VERIFIED (this project,
2026-10-05):** on one login the listing went from four accounts to eight —
the original four, one `management_type: managed` individual account, and
three additional self-directed individual accounts, each carrying a
`nickname` the owner set in the app. One of those additional accounts held
a year of trades that no read had ever seen. The two parameters are exactly
the ones the provider's own Android app sends (`AccountApi.getAccounts`
in [robinhood-decompiled](https://github.com/ScriptedAlchemy/robinhood-decompiled):
`brokerage_account_types`, `include_managed`, `include_multiple_individual`),
and several community clients send
`default_to_all_accounts=true&include_managed=true&include_multiple_individual=true`
(some add `is_default=false`, which `rhd` does not).

Fields used: `account_number` (short alphanumeric — *not* numeric), `type`
(`cash`/`margin`), `brokerage_account_type`, `buying_power`, `cash`,
`created_at`, `deactivated`, `nickname`, `management_type`, `is_default`,
`rhs_account_number`. `cash_balances` and `margin_balances` are
**mutually exclusive** by account type; a parser assuming either is always
present will trip on the other.

Three shape facts from the 2026-10-05 read:

- **`nickname`** is `""` when unset, never null live (`account-list/v1`
  omits it then).
- **`management_type`** is `self_directed` or `managed`
  (`account-list/v1`'s `management`).
- **`rhs_account_number` is an INTEGER and is not always
  `account_number`.** For most accounts the two agree digit for digit; for
  the login's legacy default account, whose `account_number` is
  alphanumeric, the integer is a different number. Other endpoints name
  accounts by it (the ACATS listing, §3.13), so a join must go through the
  account row's `rhs_account_number`, never through `account_number`.

`account-list/v1` reports `nickname`, `management` and `default: true` (the
login's default account only; omitted otherwise).

`brokerage_account_type` values seen live (2026-08-21, one four-account
login): `individual`, `ira_traditional`, `ira_roth`,
`joint_tenancy_with_ros` — note `ira_roth`, not the guessable `roth_ira`.
This is the designation `rhd` reports as `account-list/v1`'s `kind` and
`net-worth/v1`'s per-account `type`. The rows' `portfolio` key is **null**
live — see the §3.8 trap.

### 3.3 Positions — `GET /positions/`

`?nonzero=true` for current holdings (otherwise you get every position ever
held); `?account_number=<n>` to scope to one account.

**The `account_number` scoping is truthful — LIVE-VERIFIED (this project,
2026-08-21):** distinct row sets per account (3 vs 6 rows in the probe), and
every row names its own account (direct `account_number` plus an `account`
URL). That per-row self-identification is why `net-worth` can verify each
row and makes lying impossible here — in sharp contrast to the portfolio
endpoints, whose account parameter is **ignored** (§3.8).

**A position carries no symbol** — only an `instrument` URL. Symbols come from
`GET /instruments/?ids=<uuid>,<uuid>,…`, which is **batched**: resolving one at
a time would cost one request per holding against a rate-limited API. `rhd`
batches 25 at a time and, when a symbol can't be resolved, **omits** it rather
than inventing one — a wrong ticker on a tax row is worse than a missing one.
**LIVE-VERIFIED (this project, 2026-08-12):** every position's symbol resolved
through the batched lookup.

**The batch leaves some instruments out.** LIVE (2026-10-02): an equity
order from earlier in the year named an instrument that `?ids=` answered
without — no entry, no `null` — so six filled orders listed with no symbol.
The single-instrument read `GET /instruments/<id>/` answered it with its
symbol. `rhd` now reads each id the batch left out once on its own, at most
25 per invocation (a bound, never a retry); a 404 there leaves the symbol
out, and any other failure fails the command as a failed batch does. The
single read is built from the id, never from the provider's URL. Why the
batch skips an instrument is **UNVERIFIED-LIVE**: the likeliest reading is
that `?ids=` answers only current instruments, and one retired by a
corporate action (a reverse split, a ticker change) is still readable by
id. The `instrument.json` fixture models that reading (`state: inactive`).

Options positions live at `/options/positions/` — a separate read with
its own shape and traps (§3.9, `rhd options positions`).

### 3.4 Orders — `GET /orders/`

`?account_numbers=<n>`, and **`?updated_at[gte]=<ISO8601>`** — the server-side
date bound, which is what stops a multi-year account from paging its whole
history to answer "this tax year". There is no `lte` counterpart, so `--until`
is applied client-side. **LIVE-VERIFIED (this project, 2026-08-12):** a
`--since`-bounded listing returned real orders, including the `filled` and
`cancelled` shapes below.

**An unscoped read answers for the login's DEFAULT account only — not
"every account".** LIVE (2026-10-05): a downstream capture of a full year of
unscoped `/orders/` reads held none of an additional individual account's
orders, while `?account_numbers=<that account>` returned them at once; and
every row of the same capture's unscoped `/options/orders/` reads named the
default account. A read without `account_numbers` is therefore the default
account's history, and a complete household read is one scoped read per
account (`--all-accounts`, §3.14).

**Order rows name their account by URL only.** The live equity order rows
carry `account` (`…/accounts/<n>/`) and no direct `account_number`, so
`transaction/v1`'s `account_number` is parsed out of that URL when the
direct field is absent.

Fields used: `id`, `side`, `state`, `cumulative_quantity`, `average_price`,
`created_at`, `last_transaction_at`, `instrument`, `executions[]`, `fees`,
`executed_notional`. The DTO carries the `instrument` URL's UUID as
`instrument_id` on every row, with its symbol or without, so a consumer can
name, or look up, a row whose symbol did not resolve (§3.3).

Two shape facts the fixtures pin down:
- a **cancelled** order has `average_price: null` and
  `cumulative_quantity: "0.00000000"`;
- a **market** order has `price: null`. This is why the DTO reports
  `average_price` (what was achieved) rather than `price` (what was asked) —
  the latter is both absent on market orders and wrong for basis work.

**The realized-gains enrichment — LIVE-VERIFIED (this project,
2026-08-24).** The rows the endpoint already returns carry more than the
original DTO exposed; `transaction/v1` also surfaces (additively within
`/v1` — every new field optional and omitted when absent), all confirmed
against real filled orders in the owner smoke of 2026-08-24:

- **`fees`** — a flat string (`"0.02"`), documented since the sanko era.
- **`executed_notional`** — the executed dollar amount as a **nested money
  object** (`{"amount", "currency_code", "currency_id"}`), the one place
  equity orders nest money. Live-verified: the mapping read a real fill
  correctly (achieved price × quantity, to the cent). **`total_notional`**
  sits beside it in the same nested shape and is **not** the same figure —
  on a live limit order the two differed, because total reflects the
  *asked* terms (limit price × quantity) where executed reflects the
  *achieved* ones. That is the `price`-vs-`average_price` distinction
  again, and it is why the DTO surfaces only `executed_notional`: basis
  work must never read the asked figure.
- **`executions[]`** — per-fill detail, all live-verified present **on the
  wire**: `price`, `quantity`, `rounded_notional`, `settlement_date`,
  `timestamp`, `id`. The DTO's `--executions` detail surfaces
  `price`/`quantity`/`settlement_date`/`timestamp`; `rounded_notional` and
  the fill `id` stay wire-only for now (reachable via `rhd api`, pinned by
  the fixture so they're there when a consumer needs them).
  `rounded_notional` is a field the community clients don't document — only
  an old public capture (robinhood-nodets) shows it; the live wire still
  carries it. Settlement dates matter for year-boundary trades. Opt-in via
  `--executions`, because most reads don't need the noise.
- Quantities (`quantity`, `cumulative_quantity`) are 8-decimal strings on
  the wire — live-confirmed, matching the fixtures.

**Consumer contract for the realized-gains feed (this endpoint and
§3.4.1): count a row that is `filled` OR carries an executed quantity
above zero.** Live-verified 2026-08-24: a `cancelled` row usually carries
zero cumulative quantity and no executed figures — the smoke's
initially-alarming "empty sells" were exactly this — and a
**`confirmed`** row is a *resting open order*, also empty of executed
figures. **Corrected 2026-10-02:** a `cancelled` row can also carry a
**partial fill** — `cumulative_quantity` above zero with
`executed_notional` (equities), `processed_quantity` above zero with
`processed_premium` (options) — and the state
`partially_filled_rest_cancelled` exists on the wire too. Downstream
captures of this feed held such rows across several years, among them
a cancelled buy whose executed shares were later called away by an
assignment (§3.10). A consumer filtering `state == "filled"` alone drops
real shares and contracts, so a later sale or delivery finds no lot. The
CLI deliberately does not pre-filter (a resting or cancelled order is
still order history), so the gate belongs to the downstream consumer,
which must apply it before averaging or summing anything. One edge the contract must name: `state` is optional in both
DTOs and omitted when the wire doesn't carry it, so an **absent** `state`
means *unknown* and must be inspected — never treated as "not filled" and
silently dropped from a total (the same rule as `net-worth`'s absent
`covers`). Live, every row carried a state; the clause exists for the day
one doesn't.

### 3.4.1 Options orders — `GET /options/orders/` — **LIVE-VERIFIED (this project, 2026-08-24)**

Equities `/orders/` does **not** include options activity, which for an
options-heavy account is most of the realized P/L. `rhd transactions options`
surfaces this endpoint as `option-order-list/v1`. The read was built from
three community sources that agree on the envelope and top-level keys and
**disagree on the leg shape**, then confirmed end to end in the owner smoke
of 2026-08-24 (warm session; findings below the table):

| Source | Contribution |
| --- | --- |
| robin_stocks `urls.py`/`orders.py`/`export.py` | the URL; the same `?account_numbers=` / `?updated_at[gte]=` query parameters as `/orders/`; legs resolved via each leg's `option` instrument URL |
| anthonyk1225/robinhood-to-xlsx `schemas/options.json` | a public example capture: full top-level key set; legs carry **only** `id`/`option`/`position_effect`/`ratio_quantity`/`side`/`executions` |
| CIInc/robinhood-options-mobile `option_leg.dart` | a 2024+ model that parses `expiration_date`/`strike_price`/`option_type` **inline on the leg** |

Top-level keys (community consensus): `id`, `ref_id`, `chain_id`,
**`chain_symbol`** (the underlying's ticker, carried directly — no
instrument-resolution step), `state`, **`direction`** (`debit` | `credit`),
`premium`, **`processed_premium`**, `price` (per-share premium), `quantity`,
`processed_quantity`, `pending_quantity`, `canceled_quantity`,
`opening_strategy`, `closing_strategy`, `legs[]`, `time_in_force`, `trigger`,
`type`, `stop_price`, `created_at`, `updated_at`. There is no
`last_transaction_at`; the DTO's `date` is the latest fill timestamp across
the legs, falling back to `updated_at` then `created_at`.

**The leg divergence resolved live (2026-08-24): legs arrive INLINE.** Real
rows carried `side`/`option_type`/`strike_price`/`expiration_date` on the
legs themselves — the CIInc-modelled shape — and the fallback resolver
**never fired**. The resolver stays in place anyway (inline first, then
`GET /options/instruments/<id>/` — the robin_stocks path; the instrument's
type key is **`type`**, not `option_type` — deduplicated, paced at the
client's 250 ms floor, announced on stderr) because the older captured
shape is real too and the provider reshapes this API without notice. An
option URL off the API origin is refused outright (same rule as pagination
cursors — the request carries the bearer token).

**Sign convention (ours, not the wire's):** `processed_premium` arrives as an
unsigned magnitude plus `direction`. The DTO signs it by cash flow — `credit`
positive (premium received), `debit` negative (premium paid) — and carries
`direction` alongside so the signing is checkable. A zero or directionless
premium is left unsigned. Live-verified: a real filled debit order came out
correctly negative.

**Per-leg fills — LIVE-VERIFIED (this project, 2026-10-02).** With
`--executions`, each leg carries its own `executions[]` (`price` as a money
object, `quantity` in contracts, `settlement_date`, `timestamp`). One live
read of a year of options orders found fills on every leg of every filled
order, and on every filled row the legs' fills — price per share ×
contracts × 100, a sold leg receiving and a bought leg paying — summed to
the signed `processed_premium` **to the cent**, multi-leg rolls (close one
expiry, open another in one order) included. No fee sat between the two.
So the per-leg split that a multi-leg order's net premium hides is
recoverable exactly from its fills, which is what a realized-gains
consumer needs to close and open each leg's own contract
(`tests/fixture_shapes.rs` pins the identity on the fixture). A partially
filled cancelled order's legs carry the fills it did execute.

**What the 2026-08-24 owner smoke proved** (warm session, no login spent):

- The endpoint **answers** with the documented envelope and rows for a real
  options-heavy account; no extra query parameter was needed.
- Legs **inline** (above) — the resolver path never ran.
- `processed_premium` **signed correctly** per direction on real fills;
  states present on every row.
- **The states truth** (shared with §3.4's consumer contract): `cancelled`
  rows usually carry zero premium, zero processed quantity, and no
  notional; `confirmed` is a resting open order, equally empty of executed
  figures. A `cancelled` row can hold a partial fill (processed quantity
  above zero, with its premium — corrected 2026-10-02, §3.4), so
  downstream consumers **must count `filled` rows and any row with an
  executed quantity above zero**.
- `?updated_at[gte]=` / `--since` **behaved**: narrow ranges returned
  scoped result sets quickly. **Expected latency:** a full-year pull on an
  options-heavy account pages correctly but takes **minutes** — that is the
  pagination chain at the 250 ms request floor, not a hang. Narrow with
  `--since`/`--until` where a slice will do.

Still unexercised after that smoke: the leg-resolver fallback path against
the live service (its origin guard and no-op path are unit-tested offline),
and `strike_price` arriving as a JSON number (tolerated — pinned by a unit
test).

### 3.5 Documents — `GET /documents/`

The full key set, **LIVE-VERIFIED (this project, 2026-08-12)** — identical on
all 500 rows of a live first page: `id`, `url`, `account`, `type`,
**`filetype`**, `is_from_rhs`, `date` (bare `YYYY-MM-DD`), `download_url`,
`insert_1_url` … `insert_6_url`, `created_at`, `updated_at`.

**`filetype` is the field the community sources all miss**, and it matters:

- Live values: **`pdf`**, **`csv`**, **`html`**.
- Each tax season's consolidated 1099 appears **twice** under `type=1099` —
  the PDF form, then a machine-readable **CSV export** created days-to-weeks
  later. The CSV (a `1099-DIV,ACCOUNT…` header) is arguably the more useful
  artifact for tax software.
- Older `account_statement` rows can be **`html`**.
- `rhd` verifies every download against the declared filetype
  (`pk_cli_documents::verify_download` — mechanism extracted to cli-common
  v0.6.0), names the saved file with the right extension,
  and labels non-PDF variants in the listing (`… (CSV)`), since the two 1099
  rows are otherwise indistinguishable.

`?type=` filter values seen live on this account: **`1099`** (18 results),
`1099c`, `1099_crypto`, `5498`, `account_statement`, `trade_confirm` —
LIVE-VERIFIED (this project, 2026-08-12). **Not** `tax_1099`/`form_1099`
(HTTP 400, community-verified). Note the live wire strings are **lowercase** —
`1099c` where the decompiled Android enum spells it `1099C`. The enum is
authoritative for what *can* exist, not for casing. Enum
members not yet seen on the wire (UNVERIFIED casing): `account_activity_report`,
`1099R`, `1099Q`, `1042`, `1042S`, `2439`, `480_6ABCD`, `5498_ESA`, `FMV`,
`REMICS`, `SDIRA`, `ADHOC`. `rhd` keeps the provider's own word for anything it
doesn't recognize rather than flattening it to "Document" — a new form type
must stay visible.

Download: `GET <download_url>` with the **same bearer token** — LIVE-VERIFIED
(this project, 2026-08-12): a real consolidated-1099 PDF (62 pages) came back
with its `%PDF` magic intact. Whether `download_url` 302-redirects to a signed
S3 URL remains unobserved from the client's side; the code works either way
since redirects are followed transparently.

`rhd` requires the payload to match the declared filetype — `%PDF` magic for a
PDF; for text types, none of the known failure shapes (a DRF JSON error, an S3
XML error, or HTML where it wasn't promised) — before it writes anything or
reports a byte count. An expired pre-signed link answers `200` with XML or
HTML, and "downloaded 1,204 bytes" of an error page is exactly the lie this
rule exists to prevent. The check has caught a real mismatch once already: the
pre-`filetype` code demanded `%PDF` of a CSV export and correctly refused it,
which is what exposed the field.

### 3.6 Dividends — `GET /dividends/`

**LIVE-VERIFIED (this project, 2026-08-13).** The 1099-DIV raw material,
surfaced by `rhd dividends list`. A multi-year history came back on a
**single page** (`next: null`); no server-side date or account parameter is
known, so `--since/--until/-a` are applied client-side.

Key facts the code depends on:

- Like positions, **a dividend carries no symbol** — an `instrument` URL,
  resolved through the same batched `/instruments/?ids=` lookup.
- `state` ∈ `paid` | `reinvested` | `voided` (observed live). **`paid_at` is
  null exactly for `voided` rows** — date handling falls back to
  `payable_date`.
- **`reinvested` rows carry four `drip_order_*` keys the other states lack
  entirely** — absent, not null. Parsers must not require them.
- `account_number_rhs` is a **direct** account number, unlike the `account`
  URL beside it.
- `amount` is net of `withholding`; both are surfaced in the DTO so DIV box
  math is checkable. `gross_amount`, `fee`, `nra_withholding` exist on the
  wire for anyone reconciling deeper (via `rhd api`).

### 3.7 Interest — `GET /accounts/sweeps/`

**LIVE-VERIFIED (this project, 2026-08-13).** Cash-sweep interest payments —
the 1099-INT raw material, surfaced by `rhd interest list`. No community
client models this endpoint; the shape here comes from a live capture.

- Money is a **nested object** (`{"amount", "currency_code", "currency_id"}`)
  rather than the flat string most fields use. Dividends nest the same shape
  in `drip_order_execution_price` (§3.6); both read through
  `commands::money_obj_at`.
- `account_number` is direct. `pay_date` is a bare ISO date.
- Every observed row: `direction: "credit"`, `reason: "interest_payment"`.
  `payout_type` varies (`end_of_month_payment`, `eom_payment`,
  `program_opt_out`, `sweep_program_opt_out`,
  `unidentified_early_interest_payment`) and passes through verbatim.
- Date/account filters are client-side, as with dividends.

### 3.8 Net worth — computed from positions + cash (no truthful portfolio endpoint)

**There is no Robinhood endpoint that truthfully answers "what is account N
worth" — every candidate lies.** This section exists so nobody "simplifies"
`net-worth` back to a portfolio read. Two shipped designs failed live
against a real four-account login before the current one; the truth table
(all probes LIVE-VERIFIED this project, 2026-08-21, auth warm) is:

| Source | Verdict |
| --- | --- |
| Account rows' `portfolio` link | **Null on the wire** for every account — the community-documented link (`/accounts/<n>/portfolio/`) does not exist in practice. Killed design #1. |
| Bare `GET /portfolios/` | **Primary account only** (`is_primary_account: true`, one row for a four-account login) — legacy pre-multi-account behavior. |
| `GET /portfolios/?account_number=<n>` | **PARAM-IGNORED — dangerous.** Probed with all four account numbers: every query answered rows=1 referencing the **primary** account, regardless of input. An earlier "verification" was a false positive because the probed account happened to *be* the primary. The plural `?account_numbers=` is ignored identically. A client that doesn't verify the row's `account` URL will silently report the primary account's balance four times. Killed design #2 — `rhd`'s mismatch refusal caught it. |
| `bonfire.robinhood.com/phoenix/accounts/unified` | Rich JSON (`total_equity`, `total_market_value`, `uninvested_cash`, per-context keys), but its `?account_number=` is **also ignored** — all four scoped probes returned the identical `total_equity`, equal to the unscoped call. It reflects one default account context, **not** a household total. Also: `phoenix.robinhood.com` itself fails at the network layer; the phoenix API is reachable only under the bonfire host prefix. Do not use it for net-worth. |
| `GET /positions/?nonzero=true&account_number=<n>` | **Scopes truthfully** (§3.3): distinct row sets per account, every row naming its own account — per-row verification makes lying impossible. |

So `rhd net-worth` computes, per account, entirely on `api.robinhood.com`:

```
equity(n) = portfolio_cash(n)                    # the account's own /accounts/ row (§3.2)
          + Σ quantity × price                   # /positions/?nonzero=true&account_number=n
```

**Scope — a definitional decision, stated in-band.** `/positions/` covers
cash equities (stocks/ETFs) only; options positions live at
`/options/positions/` and crypto on separate services, neither of which
this command values (see §7). `rhd`'s `net-worth/v1` figure is therefore
**defined as a cash + equities figure**, and the DTO says so itself via a
`covers: ["cash", "equities"]` field — a consumer must not read `total` as
"everything at Robinhood". This is deliberately the *declared*-narrowing
option rather than a probe-and-refuse on the options endpoints, which are
themselves unverified; if options/crypto valuation lands (§7), extend
`covers` in the same change.

- **`portfolio_cash`** comes from the account's own row, which makes it
  inherently per-account (LIVE-VERIFIED present, 2026-08-21). In a margin
  account it reflects any margin debit, so provider-internal borrowing nets
  out inside its account.
- **Every position row is verified**: its `account_number` must equal the
  account queried, else the whole read is refused (exit 5) — the §3.8 rail
  that caught the portfolio endpoints lying. Rows that cannot be verified or
  valued (no account_number / quantity / instrument) are refusals too, never
  silent omissions that would understate an account.
- **Prices** come from the community-standard batch quote endpoint
  `GET /marketdata/quotes/?instruments=<url>,<url>,…` — **LIVE-VERIFIED (2026-08-21)**
  (modelled on the community record; robin_stocks reads the same data
  per-instrument via `/marketdata/quotes/{id}/`). Price used:
  **`last_trade_price`**, falling back to `last_extended_hours_trade_price`
  when the regular print is absent (the regular print is always present in
  and after a session; the extended field is null outside extended hours).
  The envelope carries `null` entries for unquotable instruments; a holding
  with no resolvable price fails the read loudly (exit 5) — never a silent
  $0 or a quietly understated account. Note the consequence: this is a
  **valuation at last trade**, so it can differ from the app's displayed
  value by quote staleness.
- **The rollup** (`total`/`assets`/`liabilities`) is client-side because no
  truthful provider total exists at any level, household or per-account.
  All arithmetic is integer fixed-point at 8 fraction digits (the API's own
  quantity precision; the first live failure showed real amounts exceeding
  the 4-decimal money convention) — quantity × price is exact in 128-bit,
  rounded half-away-from-zero back to 8 digits; no float ever touches a
  balance.

Deactivated accounts are skipped. Unlike every other read, a profile's
**persisted default account does not scope this command** — only an explicit
`-a`/`RHD_ACCOUNT` narrows it — because a config default silently turning
the household figure into one account's balance is exactly the misreport the
rollup exists to avoid.

**Status: the positions+cash pipeline is LIVE-VERIFIED (2026-08-21).** The
owner's third smoke ran the whole pipeline — accounts, per-account positions,
the batched quotes leg, portfolio_cash — and returned four DISTINCT per-account
equities (every position row account-verified), where both retired endpoints
had echoed identical primary-account figures for all four inputs.

### 3.9 Options positions — `GET /options/positions/` + instruments + marks — **LIVE-VERIFIED (this project, 2026-10-01)**

`rhd options positions` surfaces open option positions as
`option-position-list/v1`, valued at the mark. It takes three reads, each
probed once against a real options-holding account (warm session, no login
spent) before the code was written:

| Read | Shape facts |
| --- | --- |
| `GET /options/positions/?nonzero=true` | DRF cursor envelope. One row per held contract. `chain_symbol` (the underlying), `option` (instrument URL) **and** a direct `option_id`, `type` = **`long` \| `short`** (the position direction — *not* call/put), `quantity`, `average_price`, `trade_value_multiplier` (`"100.0000"`), `expiration_date` (bare ISO date — the one contract detail carried inline), `account_number` (direct) plus an `account` URL and `account_number_rhs`, `opened_at`, `last_acquired_at`, six `pending_*_quantity` fields, and the clearing-firm block `clearing_running_quantity` / `clearing_cost_basis` / `clearing_direction` (+ intraday variants). **No strike, no call/put.** Money and quantities are 4-decimal strings; `clearing_intraday_running_quantity` arrived as a bare `"0"`. |
| `GET /options/instruments/?ids=<uuid>,…` | **Batched** — the community record mostly shows the per-id `/options/instruments/<id>/`; the `ids` form answers a cursor envelope. Contract `type` (`call`/`put` — again the key is `type`, as in §3.4.1), `strike_price`, `expiration_date`, `trade_value_multiplier`, plus `long_strategy_code`/`short_strategy_code`, `expiration_datetime`, `sellout_datetime`, `formatted_strike_price`. **Rows come back in a different order than the ids were asked in** — join by `id`, never by position. |
| `GET /marketdata/options/?ids=<uuid>,…` | Envelope is **`results` only** (no `next`/`previous`). `mark_price` and `adjusted_mark_price` (tick-rounded) — **per share**, 6-decimal strings; `bid_price`/`ask_price`/`last_trade_price`; integer `*_size`, `open_interest`, `volume`; `symbol` (underlying), **`occ_symbol`** (the OCC contract identifier, ticker space-padded to six characters); greeks and `implied_volatility` as strings; `updated_at` with nanosecond precision. Joins back by `instrument_id` (or the `instrument` URL). |

**Trap — `average_price` is per contract, the mark is per share.**
`average_price` already includes the ×100 multiplier (a $1.50 premium
reads `"150.0000"`); the mark does not. The DTO normalizes both to per
share (`average_open_price` = `average_price` ÷ multiplier) and values the
position as mark × multiplier × quantity.

**Trap — two cost bases that disagree.** `average_price × quantity` and
`clearing_cost_basis` match on a position that has only been added to, and
**diverge once it has been partly closed**. Checked live against the
position's own `/options/orders/` history: the clearing figure equalled the
**FIFO** basis of the remaining lots to the cent; `average_price × quantity`
equalled a running **average-cost** basis. Tax lots are FIFO by default, so
the DTO's `cost_basis` is the clearing figure (falling back to the average
only when the wire omits it), and `average_open_price` remains what the app
displays. Neither figure is known to carry wash-sale basis adjustments — the
1099 remains the authority.

**Sign convention (ours):** `cost_basis` and `market_value` are signed by
position — long positive, short negative (`clearing_direction` `debit` /
`credit` when present, else the row's `type`) — so `unrealized_pl =
market_value − cost_basis` holds for both directions. Magnitudes are taken
from the wire before signing, because whether a short's `average_price`
arrives negative is not settled in the community record.

**Still UNVERIFIED-LIVE:**

- **Short positions.** Every live row was `long`/`debit`; the short path
  (`type: "short"`, `clearing_direction: "credit"`) is modelled and
  unit-tested, not observed.
- **Multi-account coverage of the bare call.** Every live row named the
  same account, so whether an unscoped `/options/positions/` spans every
  brokerage account in the login (as `default_to_all_accounts` does for
  `/accounts/`) is unknown. `-a` filters client-side on each row's own
  `account_number`. Under `--all-accounts` each open account is read with
  `account_numbers=<n>` — the web app's parameter, not yet tried live here;
  every row is verified against it (§3.14).
- **A missing mark** (expired or halted contract): the code omits the
  mark, market value, and P/L for that row and says so on stderr — never a
  $0 valuation — but no such row has been seen.
- `/options/aggregate_positions/` (the strategy-grouped view) remains
  unprobed; nothing needs it yet.

### 3.10 Option events — `GET /options/events/` + instruments — **LIVE-VERIFIED (this project, 2026-10-02)**

`rhd transactions option-events` surfaces exercises, assignments and
expirations as `option-event-list/v1`. These are the events neither order
feed records: an assigned short call delivers shares out of the account
with no order on `/orders/` or `/options/orders/`, so a realized-gains
workup built on the order feeds alone keeps share lots that are gone and
option lots that ended. One unparameterized read of the endpoint on a real
options-heavy account (warm session, no login spent) set the shape below;
the contract detail comes from the batched instruments read §3.9 already
verified.

| Read | Shape facts |
| --- | --- |
| `GET /options/events/` | DRF cursor envelope; 30 rows across three years answered on **one page** (`next: null`), newest `event_date` first. Every row carries the same 21 keys: `id`, **`type`** (`exercise` \| `assignment` \| `expiration` — the event type, not call/put and not long/short), `state`, `direction` (`debit` \| `credit`), `event_date` (bare ISO date), `quantity` (contracts, 4-decimal string), `total_cash_amount`, `cash_component`, `settlement_price`, `underlying_price`, **`equity_components[]`**, `option` (instrument URL) plus a direct `option_id`, `position` (an `/options/positions/` URL), `chain_id`, `source_ref_id`, `account_number` (direct) plus an `account` URL and `account_number_rhs`, `created_at`, `updated_at`. **No underlying ticker, strike, call/put or expiry** — the contract is described only through `option_id`. |
| `equity_components[]` | The share leg: one entry per exercise or assignment, empty for an expiration. `symbol` (the underlying ticker), `side` (`buy` = shares received, `sell` = shares delivered), `quantity` (shares, 8-decimal string, = contracts × 100 on every live row), `price` (per share, 4-decimal — **equal to the strike** on every live row), `instrument` (equity instrument URL), `id`. |
| `GET /options/instruments/?ids=` | As §3.9: `chain_symbol`, contract `type`, `strike_price`, `expiration_date`, `trade_value_multiplier`. Joined by `option_id`. |

What the live rows showed, by type: every `exercise` was a long call
(`debit`, one `buy` component, `total_cash_amount` = shares × strike to the
cent, a `source_ref_id` UUID); every `assignment` was a short call
(`credit`, one `sell` component, `source_ref_id` null); `expiration` rows
covered both calls and puts. No put exercise or put assignment was seen —
the mapping is the same shape with the share side reversed, unit-tested
only. `state` was `confirmed` on every row; no other state has been seen.

**Trap — an assignment's cash is net of the sale's fees.**
`total_cash_amount` on every assignment was a few cents *short* of
shares × strike (from $0.02 to about $0.50): the regulatory fees on the
share sale, deducted. An exercise's cash equalled shares × strike exactly
(a purchase carries no such fee). The DTO surfaces the wire figure as
`cash_amount`, so a consumer gets the true net proceeds; shares × price
from the component is the gross.

**Trap — an expiration's `total_cash_amount` is a bare `"0"`.** No decimal
point, where every other money field carries two or four places. The DTO
normalizes it to `0.00` and never signs it.

**Trap — an expiration row does not say whether the contract was long or
short.** Its `direction` was `credit` on every live expiration, puts and
calls alike, so it is not the position's side. An exercise is necessarily
the holder's (long) and an assignment the writer's (short); the DTO's
`position_type` says so for those two and is absent for an expiration.
The `position` URL names the position, but reading it would cost a request
per event; a consumer that tracks lots already knows which side it held.

**Trap — `underlying_price` can be null.** Present on every expiration and
exercise, null on the two **early** assignments (dated before the
contract's expiry). Exercises were all early too — 25 to 30 days before
expiry — so the event date, not the expiry, is the disposal date.

**Sign convention (ours):** `cash_amount` is `total_cash_amount` signed by
`direction` — `credit` positive, `debit` negative — the same rule as
`transactions options`' premium. Zero stays unsigned.

`cash_component` and `settlement_price` were null on every row: nothing
here was cash-settled. The DTO surfaces `cash_component` when it carries a
value, for the day an index option settles in cash.

**Still UNVERIFIED-LIVE:** put exercises and put assignments; any `state`
but `confirmed`; a populated `cash_component`; multi-account coverage of
the unscoped read (every live row named one account; `-a` filters
client-side); whether the endpoint honors a date or account query
parameter (none was tried — every filter is client-side); and pagination
beyond one page.

### 3.11 Not implemented

`/portfolios/historicals/…`,
`/options/aggregate_positions/`, `/ach/transfers/`,
`/cash_journal/margin_interest_charges/`,
`bonfire.robinhood.com/paymenthub/unified_transfers/` (cash transfers),
`api.robinhood.com/acats-aggregation/fee_reimbursements/history`, and
`minerva.robinhood.com` (card transactions). Reachable today via `rhd api
GET` — which takes a full URL, so `rhd api GET
https://bonfire.robinhood.com/<path>` reaches the second host (§3.13).

### 3.12 Deliberately absent

There is no order-entry, transfer, or account-settings code path in this
binary. `rhd transfers acats` **reads** transfer history; nothing in `rhd`
can initiate one. `rhd api` accepts `GET` only.

### 3.13 ACATS transfers — `GET bonfire.robinhood.com/acats/?both_directions=true` — **LIVE-VERIFIED (this project, 2026-10-05)**

Shares that move between brokerages by ACATS arrive **without an order**,
so neither order feed records them: a realized-gains consumer walking
orders sees a sale with no buy. `rhd transfers acats`
(`acats-transfer-list/v1`) reads the provider's record of them.

**Three candidate endpoints, probed once each on 2026-10-05:**

| Endpoint | Source | Live answer |
| --- | --- | --- |
| `bonfire.robinhood.com/acats/?both_directions=true` | Android app `AcatsApi.getAcatsTransfers(cursor, both_directions)` ([robinhood-decompiled](https://github.com/ScriptedAlchemy/robinhood-decompiled)); seen on the web app's account-history and transfers pages | **The listing.** Earlier years' incoming transfers, settled and rejected |
| `api.robinhood.com/acats/` | an old community map, and the web app's account-history page | `{"next": null, "previous": null, "results": []}` — empty |
| `api.robinhood.com/nimbus/v1/asset_transfers` | the web app's account-history page | `{"assetTransferRecord": [], "previousCursor": "", "nextCursor": ""}` — empty, camelCase |

`rhd` reads the first. Its envelope is `{results, prev, next}` — **`prev`,
not `previous`** — and the cursor is followed only on the bonfire origin
(`Rh::paginate_at`): the bearer token rides every request, so a `next`
pointing anywhere else is refused, as on the API host (§3.1).

**Row shape** (key set from the live read; values in the fixture are
synthetic): `id` (uuid), `direction` (`incoming`; `outgoing` is the other
documented value), `phase` (`settled`, `rejected`; in-flight phases exist),
`transfer_type` (`full`, `residual` — a later sweep of leftover cash;
`partial` is the other documented value), `requested_at` (RFC 3339 with a
`+00:00` offset), `settlement_date` (`YYYY-MM-DD`, null until settled),
`estimated_settlement_date`, `last_activity_at`, `rhs_account_number`,
`contra_account_name`, `contra_account_number`, `contra_broker_name`,
`contra_broker_logo`, `contra_dtcc_number`, `control_number`,
`reject_reason`, `reject_reason_enum`, `retry_steps`, `market_value`
(null live), `bonus_match`, `gold_deposit_boost`,
`cash_advance_grant_date`, `estimated_cash_advance_grant_date`, `user_id`,
and `assets[]`: `{asset_type: equity|cash, asset_id, instrument_id,
direction: long|short, quantity, iso_currency_code}`.

**The traps:**

- **No cost basis, anywhere.** Not on the transfer, not on an asset —
  quantities only (`market_value` was null on every live row). The basis
  travels between the brokers' books, not through this API; a consumer
  must carry it over from the sending broker's lots. `acats-transfer/v1`
  emits no basis field rather than a misleading one.
- **The account is named by `rhs_account_number`, an integer**, which is
  not always the `account_number` other endpoints use (§3.2). `rhd` joins
  it through the accounts listing and reports `account_number` +
  `account_kind`; a reference that matches no account in the login is kept
  as `rhs_account_number` (string) so the row stays attributable by hand.
- **`reject_reason` is filled on SETTLED rows** with a generic
  support-link string. It is not a reason; `rhd` reports it only on
  `rejected` transfers.
- **`contra_broker_name` is null on a residual sweep** even when the full
  transfer it follows names the broker.
- **Quantities carry six decimals on equity legs** (`"10.000000"`) and four
  on cash legs (`"19.6900"`); a cash leg's `direction: short` is a debit
  carried across (a transfer fee, a debit balance), `long` a credit.
- Equity legs name their instrument by bare uuid (`instrument_id`); `rhd`
  resolves symbols with the batched instruments read (§3.3) and omits one
  that does not resolve.

**The gap — an ACATS into an additional individual account is in no known
listing.** LIVE (2026-10-05): a transfer from another broker in 2026 into
one of the login's additional self-directed individual accounts (§3.2)
appeared in **none** of the three endpoints above, while earlier years'
transfers into the original accounts did. Why is **UNVERIFIED** — the
likeliest readings are that transfers into the newer account kinds are
recorded by a service none of these reads, or that the sending broker
pushed the shares by a mechanism Robinhood does not list as ACATS. Until a
listing is found, a consumer must **infer** a transfer-in from the
receiving account itself: shares appear in its positions (and are sold in
its orders) with no buy before them. `--all-accounts` (§3.14) is what makes
that account's positions and orders visible at all.

`acats-transfer/v1` fields: `id`, `date` (settlement date, else the
request date — what `--since/--until` filter on and what the list is sorted
by, newest first), `direction`, `state` (the wire's `phase`, verbatim),
`transfer_type`, `requested`, `settlement_date`,
`estimated_settlement_date` (only while unsettled), `account_number`,
`account_kind`, `account_default` (`true` when the account is the login's
default, omitted otherwise — the same mark the `--all-accounts` reads
carry, so a consumer keeping the default account's rows in one book can
join these too), `rhs_account_number` (only when unmatched),
`contra_broker`, `contra_dtcc_number`, `reject_reason` (only when rejected), and `assets[]`
(`asset_type`, `symbol`, `instrument_id`, `quantity`, `direction`,
`currency`). `-a` keeps one account's transfers.

### 3.14 Every account — `--all-accounts` — **UNVERIFIED-LIVE as a whole**

Live so far (2026-10-05): the full accounts query (§3.2) and
`/orders/?account_numbers=<n>` scoping to an additional individual
account (§3.4). **Not yet live**: the installed build's fan-out end to end,
and `account_numbers` on `/options/orders/`, `/options/events/` and
`/options/positions/` — the parameter the provider's web app sends there,
but unproven here. The per-row verification below is what keeps an ignored
parameter from misattributing rows in the meantime: it refuses the read
rather than trusting it.

Because an unscoped order read answers for the default account only
(§3.4), and the accounts listing itself hides managed and additional
individual accounts unless asked (§3.2), "read everything" has to be built:
`positions list`, `options positions`, `transactions list`, `transactions
options` and `transactions option-events` take **`--all-accounts`**, which

1. enumerates the login's accounts once (§3.2's full query) — every
   account with an `account_number` for the history reads (a closed account
   can hold this year's trades), active accounts only for the holdings
   reads;
2. issues one scoped read per account: `account_number=<n>` on
   `/positions/`; `account_numbers=<n>` on `/orders/`, `/options/orders/`,
   `/options/events/` and `/options/positions/` (the last two are the
   parameter the provider's web app sends on those endpoints);
3. **verifies every returned row names the account it was requested for** —
   its `account_number`, else the number in its `account` URL. A row for
   another account means the parameter was ignored; a row naming none
   cannot be attributed. Either refuses the whole read (exit 5). This is
   the §3.8 rail that caught the portfolio endpoints lying, applied to
   every fan-out read;
4. tags every row with `account_number`, `account_kind` (the §3.2
   designation: `individual`, `ira_traditional`, `ira_roth`,
   `joint_tenancy_with_ros`, …) and, on rows from the login's default
   account, `account_default: true` (omitted otherwise) — so a consumer
   holding older unscoped captures (default account only, untagged) can
   tell which account those rows belonged to;
5. merges, then sorts newest first and applies `--limit` across the merged
   set.

The fan-out is bounded — one pass over a handful of accounts, each read
paginated under §3.1's cap — with no retry anywhere: a failed account read
fails the command. `--all-accounts` conflicts with `-a/--account` (and
`RHD_ACCOUNT`), a usage error raised before the keychain or the network is
touched; a profile's persisted default account is ignored under it.

---

## 4. Errors, limits, and lockout

Robinhood runs Django REST Framework and renders errors **compactly**:
`{"detail":"..."}` with no space after the colon.

| Case | HTTP | Body | Confidence |
| --- | --- | --- | --- |
| Wrong credentials **or a bot block** | 400 | `{"detail":"Unable to log in with provided credentials."}` | WELL-ATTESTED |
| Expired/invalid bearer | 401 | `{"detail":"Incorrect authentication credentials."}` | WELL-ATTESTED |
| Rate limited | 429 | `{"detail":"Request was throttled. Expected available in 51 seconds."}` + `Retry-After` header | WELL-ATTESTED |
| Device approval needed | 400 | `{"verification_workflow":{...}}` | WELL-ATTESTED |
| Second factor | 400 | `{"mfa_required":true,"mfa_type":"sms"}` | WELL-ATTESTED |
| Outdated client | 400 | `{"detail":"This version of Robinhood is no longer supported…"}` | WELL-ATTESTED |
| Forbidden | 403 | **UNKNOWN** — JSON, but with *no* `detail` key (a real report shows `KeyError: 'detail'`) | UNVERIFIED |

The 403 body is deliberately **not** fixtured: inventing a plausible `detail`
would encode a guess as a contract.

### 4.1 How `rhd` maps them

`json_response` checks **shape before status**, because a lapsed session often
comes back as an HTML login page with a `200`. HTML where JSON was expected is
an auth failure (exit 3), not data. The exceptions are a 429 and a 5xx, read by
status whatever the body: a throttle or an outage says nothing about the session.

401/403 → exit 3 · 404 → exit 4 · 429 and other non-2xx → exit 5.

### 4.2 Lockout risk — why there is no retry anywhere

Community-observed (Robinhood publishes nothing):

- **2-3 failed logins → account-wide lockout, ~5-10 minutes.** pyhood's
  guidance is to never retry a failed login inside 5 minutes.
- **Too many attempts → IP-level block, ~12 hours.**
- **Polling `get_prompts_status` too fast → 429 and a ~12-hour block.**
- Repeated device-approval failures can escalate to a photo-ID/bank identity
  check.
- Safe read pace: pyhood enforces **250 ms** between all requests.

So, in code: no loop around login, ever (the one implicit re-authentication is
a token *refresh*, in `Ctx::access_token`); a 250 ms floor between every request (`Rh::pace`); and the approval
poll fixed at 10 s intervals, bounded at ~2 minutes. Neither browser path
(§2.8) makes a login attempt from `rhd`: with `--browser` the owner signs in on
Robinhood's own page, and `rhd`'s one request is an ordinary authenticated
read, so a bad capture or paste costs nothing against these limits.

---

## 5. Terms of service — an honest reading

Retrieved 2026-08-12. **Not legal advice.**

The widely-cited "no data mining, robots, or similar data gathering tools"
clause is **not** in the brokerage Customer Agreement. It appears in *Sherwood
Media*'s T&C (Robinhood's news arm) and, differently worded, in the Robinhood
Money spending-account agreement — different products and entities.

The **brokerage Customer Agreement** (revised 2026-07-06) contains no
anti-scraping or "no access except through our interface" clause. What does
bear on programmatic use:

- **§4.11 No Business Use** — the platform is for "personal, non-business,
  non-commercial use". A personal read-only tax tool sits comfortably inside
  this; a commercial product would not.
- **§13** — Robinhood may restrict or terminate access at any time, at its sole
  discretion, without notice.
- **§29** — the licensed *API Package* requires written consent. Written against
  the official offering; it does not name the private endpoints on its face.

**Official alternatives:** the Crypto Trading API (2024, crypto only), and
"Agentic Trading" via MCP at `agent.robinhood.com/mcp/trading` (announced
2026-05-27, equities, beta). There is still **no official REST equities API for
retail**.

**Consequences, factually:** there are **no well-attested reports of an account
being banned for using robin_stocks or a similar client.** The only artifact is
an unverified ~2019 warning email of unknown outcome. What *is* well-attested is
rate limiting, temporary IP blocks, and auth-flow breakage. Robinhood's own
account-restrictions article does not list automated access among its reasons.
Robinhood nonetheless reserves broad discretion to terminate, so the honest
summary is: **low observed risk of account action, non-zero and entirely at the
provider's discretion, and a real risk of temporary lockout if you retry.**

---

## 6. The first live session — what 2026-08-12 proved and disproved

The owner's first-login checklist (the previous content of this section) was
executed against a real account on **2026-08-12**, owner present, one login
profile, following exactly the §6 sequence: profile → credential from the
password manager via stdin → one login attempt.

**Verified live that day:**

- **Login via the sheriff `prompt` workflow (§2.3)** — including the non-TTY
  path: the challenge parked in the keychain, the owner approved on the phone,
  and `--resume` completed that same attempt. `access_token`, `refresh_token`,
  and `device_token` all persisted; the parked entry was consumed single-use.
- **`auth status --verify`** reported `session_valid: true` with an expiry ~6
  days out (§2.1).
- **`accounts list`** returned all four brokerage accounts (owner-confirmed
  count) under `default_to_all_accounts=true` (§3.2).
- **`positions list`** populated every symbol through the batched
  `/instruments/?ids=` lookup (§3.3).
- **`transactions list --since`** returned real orders, including the
  `filled`/`cancelled` shape facts the fixtures pin (§3.4).
- **`documents list`** walked 1,268 documents (pagination, §3.1);
  `--type 1099` returned 18; a real consolidated-1099 **PDF downloaded with
  `%PDF` confirmed** (§3.5).
- **The magic-bytes rule caught a real mismatch**: the newest `1099` document
  was a **CSV export**, the pre-`filetype` code refused it, and chasing that
  refusal surfaced the `filetype` field (§3.5). The failure was the system
  working. After the per-filetype fix, the same CSV (113 KB, `1099-DIV,…`
  header) and an `html` account statement both downloaded end-to-end with the
  installed binary, correctly named and extensioned.

**Disproved / worse than documented:**

- **A second login re-challenges even with the persisted `device_token`**
  (§2.2) — and the re-challenge prompt never surfaced on the phone at all.
  Checklist item 5's "the token is not being persisted or reused" explanation
  was ruled out in code; the observed behavior is the provider's. Password
  login is owner-present-only; refresh is the unattended path.
- **Page size on `/documents/` is 500, not ~100** (§3.1).
- **The decompiled enum's casing is wrong for the wire**: live documents say
  `1099c`, not `1099C` (§3.5).

**Still UNVERIFIED-LIVE after that session:**

- The `sms`/`email` **code** challenge path (`--code`) — only the `prompt`
  workflow was exercised.
- The legacy `challenge` object (§2.4).
- **Refresh-token rotation write-back** (§2.5) — the session was too fresh to
  need a refresh.
- The 403 body shape (§4).
- The read-only secondary token (§2.7/§7), options endpoints (since verified: orders §3.4.1 on 2026-08-24, positions §3.9 on 2026-10-01).

**Verified 2026-08-13, in the follow-up session:** `/dividends/` and
`/accounts/sweeps/` captured and shipped as `dividends list` / `interest
list` (§3.6, §3.7), and `documents download --all` exercised live with
`--type`/`--since` scoping (each file verified against its declared
filetype). **Disproved the same day:** the stored session bundle carries no
`read_only_secondary_access_token` — the live login never returned one
despite sending the request flag (§2.7), so the §7 read-only-credential
hardening is blocked by the provider, not by an unwritten patch.

**Verified 2026-08-21 (two `net-worth` live smokes, owner present):** both
shipped `net-worth` designs **failed live**, and the full diagnosis became
the §3.8 truth table. Disproved across the session: the account rows'
`portfolio` link (null on all four rows of a real login); bare
`/portfolios/` as an enumerator (primary account only); and — the sharpest
lesson — `GET /portfolios/?account_number=<n>` **ignores its parameter and
echoes the primary account for every input**. Mid-session this doc briefly
claimed the query-param form live-verified: that was a **false positive**
(the probed account happened to be the primary), corrected the same day
when the second smoke's per-row account check refused the other three
accounts. The bonfire-hosted phoenix `accounts/unified` endpoint was probed
too and ignores its account parameter identically (§3.8). Positively
verified: positions' `?account_number=` scopes truthfully with per-row
account refs (§3.3); account rows carry per-row `portfolio_cash`; live
`brokerage_account_type` values are `individual` / `ira_traditional` /
`ira_roth` / `joint_tenancy_with_ros` (§3.2). The first failure ("could not
sum the equity") also showed a live amount exceeding the 4-decimal money
convention; all net-worth arithmetic now runs at 8-digit fixed point. The
replacement positions+cash pipeline (§3.8) — including the marketdata quotes
leg — passed the third smoke the same day, end to end: four distinct
per-account figures where every lying endpoint had returned identical ones
(LIVE-VERIFIED 2026-08-21).

**Verified 2026-08-24 (owner smoke, warm session), same-day as shipping:**
the equity-order enrichment and the entire options orders read, end to end.
Positively verified: `executed_notional` read correctly off a real fill;
`total_notional` is live and **differs** from executed on limit orders
(asked vs achieved — disproving this doc's brief "null on share-quantity
orders" guess); executions carry a per-fill **`rounded_notional`** no
community client documents (§3.4); `/options/orders/` answers with legs
**inline** (strike/expiry/type on the leg — the resolver fallback never
fired); `processed_premium` signed correctly on a real debit fill;
`?updated_at[gte]=` scoped both feeds quickly for narrow ranges (a
full-year options pull pages correctly but takes minutes at the request
floor — §3.4.1). The smoke's one scare taught the states truth: seemingly
empty sell rows were `cancelled`/`confirmed` orders, which legitimately
carry no executed figures — recorded as the feed's consumer contract
(§3.4; corrected 2026-10-02 for partial fills on cancelled rows). Still unexercised: the leg-resolver
fallback against the live service.

**Verified 2026-10-01 (warm session, one read per endpoint):** open option
positions end to end — `/options/positions/?nonzero=true`, the batched
`/options/instruments/?ids=`, and `/marketdata/options/?ids=` (§3.9).
Learned: positions carry no strike or call/put; the instrument batch
answers out of request order; `average_price` is per contract while the
mark is per share; and `clearing_cost_basis` is the FIFO remaining-lot
basis, which diverges from `average_price × quantity` after a partial
close (checked against the position's own order history). Still unseen:
short positions, and whether the unscoped read spans every account.

**Verified 2026-10-02 (warm session, one read of the new endpoint):**
`/options/events/` end to end, with the batched instruments read §3.9
already trusted (§3.10). Learned: events carry no contract detail beyond
the instrument id; the share leg moves at the strike; an assignment's cash
is net of the sale's fees; an expiration's cash is a bare `"0"` and its
row does not name the side that lapsed; early assignments carry a null
`underlying_price`.

**Live 2026-10-27 (owner present): the password login is unusable.** Every
`rhd auth login` raised the sheriff `prompt` workflow, `--channel email`
included, and the approval request never surfaced in the phone app. The owner
reinstalled the app, signed in and restarted it; a `--resume` poll (12 × 10 s)
then timed out with no prompt shown. This is the 2026-08-12 re-challenge
failure (§2.2) on every attempt rather than on a second login. The owner could
still log in at robinhood.com in a desktop browser, so `rhd auth login
--session-stdin` (§2.8) was built the same day to import that session, and
`rhd auth login --browser` (§2.8) followed on 2026-10-29 to read it out of a
sign-in window instead of a paste. Neither has been run live yet; §2.8 lists
what the first runs will prove.

When something here is confirmed, move it up and say how it was confirmed.
When something is disproved, fix the code and the doc in the same commit.

---

## 7. Follow-ups

- **Use the read-only secondary token** (§2.7) for reads — would make
  read-only an enforced property of the *credential*, not just of the code.
  The live password login of 2026-08-12 returned no such token despite the
  request flag (probed 2026-08-13), but the web app requires one on every
  login (§2.8, provider code), so an imported `web:auth_state` should carry
  it — the import reports whether it did. The endpoint-coverage probe still
  has to run before swapping it in.
- **Live-verify the browser sign-in** (§2.8): the first `--browser` run
  proves the sign-in in a kept-profile Chrome, the capture, the proving
  read and the stored bundle; the first renewal (days later) proves renewal
  with the web's refresh token and device id. Move each §2.8 UNVERIFIED-LIVE
  line up as it is seen.
- **Renew on a 401, not only at the stored expiry.** `Ctx::access_token`
  renews only when the bundle's expiry has passed. An imported session whose
  token is not a JWT has no known expiry, so it would never renew on its
  own; neither would a session the browser revoked early.
- **Ask for the read-only token on renewal**, as the web app does
  (`create_read_only_secondary_token: true`, §2.8). Untested against the
  live renewal, which itself is UNVERIFIED-LIVE (below).
- **Options coverage** — `/options/orders/` shipped 2026-08-24 as
  `rhd transactions options` (§3.4.1) and open positions shipped
  2026-10-01 as `rhd options positions` (§3.9), and exercises, assignments
  and expirations shipped 2026-10-02 as `rhd transactions option-events`
  (§3.10), each LIVE-VERIFIED the day it shipped. Still missing:
  `/options/aggregate_positions/`, which nothing needs yet.
- **Options/crypto valuation for `net-worth`** — the figure is currently a
  declared cash + equities scope (§3.8, the DTO's `covers` field). The options
  valuation now exists (§3.9's positions × marks pipeline); folding it into
  `net-worth` would widen `covers` in the same change; alternatively a cheap probe could *refuse* accounts
  holding unvalued option positions, once that endpoint's shape is trusted.
- **Server-side filters for dividends/sweeps** — no date or account query
  parameter is known for either (§3.6, §3.7), so `rhd` filters client-side.
  Cheap to probe for once, costly to assume wrongly.
- **Write back rotated refresh tokens** — refresh rotates the token (§2.5) and
  `Ctx::access_token` already persists the new bundle, but this has never been
  exercised against a real rotation.
- **`--type` values beyond the six seen live** (§3.5) are accepted and passed
  through unvalidated; if the provider 400s, the user sees an upstream error.
  Tighten once more of the enum's wire strings are confirmed — remembering the
  casing trap (`1099c`, not `1099C`).
- **Find where an ACATS into an additional individual account is recorded**
  (§3.13's gap). Candidates not yet read: the Android app's
  `acats/detail/out/?rhs_account_number=` and `acats/detail/{id}/`, and
  `bonfire.robinhood.com/equities/history/{id}`. One read each, once a
  candidate id is known.
- **Dividends, interest and documents across accounts.** `/dividends/` and
  `/accounts/sweeps/` already return rows naming their account (filtered
  client-side, §3.6/§3.7); whether they cover the additional individual and
  managed accounts unscoped is **UNVERIFIED-LIVE**.
