# Coin Purchases (Stripe) — Setup

The code is built and shipped. Buying coins won't work until you connect a
Stripe account and deploy the two edge functions. Everything below can be done
in **test mode** first (fake cards, no real money). Nothing charges a real card
until you swap test keys for live keys.

## What's already in the app
- **Client:** a "GET COINS" section at the top of the Shop with three packs
  (500 / 3,000 / 10,000 coins). Tapping a pack calls the `create-checkout`
  function and redirects to Stripe. On return, the wallet refreshes.
- **Server:** two edge functions in `supabase/functions/` and a locked-down
  `credit_tokens` SQL function (section 9 of `supabase-migrations.sql`).
- **Security:** coins are only ever granted by the webhook *after* Stripe
  confirms payment, credited by a service-role-only function, idempotent on the
  Stripe session id (a re-sent webhook can't double-credit).

## One-time setup

### 1. Run the SQL
In the Supabase SQL editor, run **section 9** of `supabase-migrations.sql`
(the `credit_tokens` function + the unique constraint).

### 2. Create a Stripe account
- Sign up at https://stripe.com and stay in **Test mode** (toggle, top right).
- Grab your **test secret key** (`sk_test_…`) from Developers → API keys.

### 3. Set the edge-function secrets
With the Supabase CLI (logged in, project linked):
```
supabase secrets set STRIPE_SECRET_KEY=sk_test_xxx
supabase secrets set APP_URL=https://wordflipgame.netlify.app
```
`SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` are
provided automatically to edge functions.

### 4. Deploy the functions
```
supabase functions deploy create-checkout
supabase functions deploy stripe-webhook --no-verify-jwt
```
(`--no-verify-jwt` on the webhook — Stripe calls it with a Stripe signature, not
a Supabase login.)

### 5. Register the webhook in Stripe
- Stripe Dashboard → Developers → Webhooks → **Add endpoint**.
- URL: `https://<your-project-ref>.supabase.co/functions/v1/stripe-webhook`
- Events to send: **`checkout.session.completed`**
- Copy the endpoint's **Signing secret** (`whsec_…`) and set it:
```
supabase secrets set STRIPE_WEBHOOK_SECRET=whsec_xxx
```

### 6. Test it
- Open the app, go to Shop → GET COINS, pick a pack.
- On the Stripe page use test card `4242 4242 4242 4242`, any future expiry, any CVC.
- After paying you'll return to the app; the wallet should tick up within a few
  seconds (the webhook credits it).

## Going live
- Complete Stripe's business/activation (bank account, tax, identity).
- Switch Stripe to **Live mode**, get the **live** `sk_live_…` and a **live**
  webhook signing secret, and re-set both secrets. Redeploy nothing else.
- **Before taking real payments** you need a **Privacy Policy** and **Terms of
  Service** page linked in the app (Stripe and app stores expect this). Ask and
  I can draft starter versions.

## Prices / packs
Defined in **two places that must match**:
- Client display: `TOKEN_PACKS` in `index.html`
- Server truth: `PACKS` in `supabase/functions/create-checkout/index.ts`
Change amounts/coins there (the server value is what's actually charged).

## Cosmetic bundles (theme + matching icon)
Featured "bundles" (e.g. Neon Pack, Vaporwave Pack) sell a theme + its matching
tile back together for real money. They ride the SAME Stripe setup as coins —
**no extra Stripe products to create.** Once the steps above are done, bundles
work automatically.

- Client display: `BUNDLES` in `index.html`
- Server truth: `BUNDLES` in `supabase/functions/create-checkout/index.ts`
  (each bundle's `amount` in cents + which `theme`/`back` it grants)
- On payment, `stripe-webhook` grants both cosmetics as ownership rows
  (`theme-<id>` + `tileback-<id>`) — the same rows the shop reads for "owned".

Until Stripe is configured, the bundle buttons simply say the purchase isn't
available yet (they fail soft, exactly like the coin packs).
