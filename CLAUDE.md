# WordFlip — Project Guide

Word puzzle PWA. Flip 4-letter tiles to find hidden words; daily challenge, solo,
online/local multiplayer, coin economy, cosmetics, achievements, leaderboard.

## Architecture (read this first)

- **Single-file app: `index.html`** (~6500 lines) holds the entire React app in one
  `<script type="text/babel">` block. **No build step** — React 18, ReactDOM, and
  Babel-standalone are loaded as self-hosted UMD bundles (`react.min.js`,
  `react-dom.min.js`, `babel.min.js`, `supabase.min.js`) and Babel transforms the
  JSX **in the browser at runtime**.
- **Styling is inline** (`style={{…}}`) with CSS custom properties (`--wf-*`) for
  theming. No CSS framework, no separate stylesheet.
- **PWA**: `sw.js` (service worker) + `manifest.json`. HTML is network-first (always
  fresh), assets cache-first. Static legal pages: `privacy.html`, `terms.html`.
- **Deploy = push to `main`** → Netlify auto-deploys (site: wordflipgame.netlify.app).
- `netlify.toml` proxies `/sb-proxy/*` → the Supabase project. The client calls
  Supabase through this **same-origin proxy** to survive browser tracking-prevention
  / CDN blocking.

### ⚠️ Two rules for every deploy
1. **Bump `VERSION` in `sw.js`** (e.g. `wordflip-v105` → `v106`) — this is what forces
   installed PWAs to pick up the new build. Skipping it means users stay on the old
   version.
2. **Syntax-check the JSX before pushing.** There's no compiler to catch errors. Load
   `babel.min.js` in Node via `vm`, extract the `text/babel` script block from
   `index.html`, and call `Babel.transform(code, { presets: ['react'] })`. If it
   throws, the app is broken. (A throwaway `check.js` in the scratchpad does this;
   re-create it as needed.)

## Backend — Supabase (project ref `vznuengepsbnmgwfyadr`)

Postgres + Auth (JWT) + Realtime + Edge Functions. Edge functions in
`supabase/functions/`: `create-checkout` (Stripe), `stripe-webhook` (credits coins),
`send-reminders` (web push).

- **`supabase-migrations.sql`** is a **re-runnable disaster-recovery RECORD** of the
  whole schema, organized in numbered sections (§1…§20). It is NOT auto-applied.
- **Applying SQL**: there is usually **no Supabase MCP tool in-session** — the user
  runs SQL manually in the Supabase SQL editor. Hand them paste-ready SQL and, for
  anything you want verified, a self-checking harness (see Testing below).

### Data model (key tables)
- `wallets(user_id, balance)` — coins.
- `player_progress(user_id, career_points)` — cumulative career total (rewards ladder).
- `token_transactions(user_id, amount, reason)` — ledger. **`UNIQUE(user_id, reason)`
  is the idempotency key** for every grant/spend.
- `inventories(user_id, hint, xray, freezes, megahint, undo)` — power-ups (note the
  column is `freezes`, plural — FREEZE is a reserved word).
- `item_prices(kind, item_id, price)` — server-owned prices (kind: powerup/theme/tileback).
- `earn_rules(event, flat, rate, max_score, adds_career, clamp_over)` — server-owned
  payouts: `amount = flat + floor(rate*score)`, per-event score ceiling.
- `powerup_rewards(reward_id, item, amount, points_required)` — career reward ladder.
- `daily_scores(user_id, day_key, score, turns, elapsed, wrong_guesses, blocks, helps)`
  — leaderboard rows. `blocks` is the 🟩🟨🟥 emoji string.
- `profiles(user_id, username)`, `promo_codes`.

## Economy — SERVER IS AUTHORITATIVE (core security invariant)

The server owns **every coin amount and price**. The client sends **intent only**
(an event key / item id / reward id) — **never a value**. This is deliberate and must
not be loosened (real-money purchases exist).

- **Earn**: `grant_earn(p_event, p_ref, p_score?)` → looks up `earn_rules`, enforces
  the per-event ceiling (reject for hard-bounded daily, clamp for unbounded solo),
  grants coins **and** career under the **one** `(user_id, reason=p_ref)` idempotency
  key. Client wrapper: `grantEarn` / `grantEarnIfSignedIn`.
- **Buy cosmetic**: `purchase_cosmetic(p_kind, p_id)` → server price from `item_prices`.
- **Buy power-up**: `buy_powerup(p_item)` → server price. Client wrapper: `buyItem`.
- **Claim ladder reward**: `claim_powerup_reward(p_reward_id)` → verifies
  `career_points ≥ threshold` server-side.
- All RPCs are `SECURITY DEFINER`, use `auth.uid()`, RLS enabled. Price/earn tables are
  **read-only** to authenticated (writes REVOKEd).
- **Legacy RPCs `add_tokens` / `spend_tokens` / `buy_item` / `add_career_points` are
  REVOKEd from `PUBLIC, anon, authenticated`** — do not resurrect them. (Revoking from
  `anon, authenticated` alone is NOT enough: `CREATE FUNCTION` grants EXECUTE to
  `PUBLIC` by default, so you must revoke from `PUBLIC` too.)
- Future multiplayer→career must route through `grant_earn` (an `adds_career` event),
  never a standalone career-writing RPC.

### Auth gotcha
Wrap **every** signed-in read/write in `ensureFreshSession()`. A day-old JWT 401s
silently, and the catch blocks fall back to empty/default state — which historically
caused "my purchase disappeared" bugs. The economy client wrappers already do this.

## Gameplay & scoring

- **Daily**: `getDailyWords()` → 4 words from `ALL_WORDS_4`, date-seeded. `maxTurns=16`.
- **Solo**: `startSolo(large)` → 4 or 9 words (`ALL_WORDS_9`). **No turn cap.**
- **`scoreCalc(ms, wordResults, turns, bonusPts)`** =
  `green×300 + yellow×100 + timeBonus + efficiencyBonus + bonusPts`
  - `timeBonus = max(0, 600 − seconds)`
  - `efficiencyBonus = max(0, (16 − turns) × 50)`
- **The "16 guesses" model**: you start with 16 guesses; **every 4-tile attempt —
  correct word, wrong guess, OR bonus word — spends one.** `turns` = total attempts.
  Efficiency = 50 per *unused* guess. A bonus word is therefore net 0 (spends a guess
  −50, pays +50). Shown as "🎯 Efficiency bonus — N remaining guesses × 50".
- `wrongGuesses` = **true misses only** (guesses forming no valid word). Used for
  achievements (`no_wrong` / Sharpshooter, `butterfingers`) — NOT for scoring.
- Share/leaderboard show `turns` as "N guesses" (total used) + a derived bonus-word
  count. Solo shows the guess count on the results screen (no share/leaderboard).
- **Career points** = cumulative score; drives `REWARD_LADDER` (cosmetics + power-ups).
  Added server-side inside `grant_earn` for daily/solo.
- Coins are **signed-in only**; client `TOKENS`/price constants are **display-only**
  mirrors of `earn_rules`/`item_prices` (keep them in sync or the preview lies).

## localStorage keys (client cache)

`wf_profile`, `wf_balance`, `wf_career`, `wf_inv_*` (power-up counts), `wf_achievements`,
`wf_ach_paid`, `wf_rewards_claimed`, `wf_rewards_seen`, `wf_games_played`, `wf_tileback`,
`wf_career_migrated_<uid>`, and date-scoped `<dateKey>_done` / `_helps` / `_undo`.

## Testing economy RPCs (impersonation harness)

To test RLS/REVOKE/`auth.uid()` behavior against the live DB safely: run inside a
`BEGIN … ROLLBACK` transaction, impersonate a real user with
`set_config('request.jwt.claims', json_build_object('sub', <uid>, 'role','authenticated')::text, true)`,
and `SET LOCAL ROLE authenticated` for privilege/lock tests. Collect PASS/FAIL into a
transaction-local GUC (`set_config('tt.rN', …, true)` — any role can) and `SELECT` them
at the end (the SQL editor hides `RAISE NOTICE` and blocks temp-table writes under the
`authenticated` role). Everything rolls back — safe on prod.

## Conventions

- Match surrounding code: inline styles, `'JetBrains Mono'` for mono text, `'Fraunces'`
  for headings, terse comments explaining *why*.
- Commit + push to `main` to ship. Keep commit messages descriptive.
- Prices/payouts change → update BOTH the DB (`earn_rules`/`item_prices`) and the
  display-only client constants.
