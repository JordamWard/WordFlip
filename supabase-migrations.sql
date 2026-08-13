-- WordFlip Supabase Migrations
-- Run these in the Supabase SQL editor at https://supabase.com/dashboard
-- Project: vznuengepsbnmgwfyadr
--
-- PURPOSE: Fix (1) mystery account display, (2) scores not saving to leaderboard

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. UNIQUE constraint so upsert on daily_scores(user_id, day_key) works
-- ─────────────────────────────────────────────────────────────────────────────
-- (Postgres has no ADD CONSTRAINT IF NOT EXISTS — guard with a DO block so
-- this file stays re-runnable top to bottom.)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'daily_scores_user_id_day_key_key') THEN
    ALTER TABLE public.daily_scores
      ADD CONSTRAINT daily_scores_user_id_day_key_key UNIQUE (user_id, day_key);
  END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Trigger: auto-create profile row when a new user signs up
-- ─────────────────────────────────────────────────────────────────────────────
-- Hardened: the email-prefix fallback is sanitized to satisfy the profiles
-- username CHECK (^[a-zA-Z0-9_]{3,20}$). Without this, an email like
-- "john.doe@x.com" (dot) or "jo@x.com" (too short) would violate the CHECK and
-- — because this trigger runs during signup — abort the signup itself. The app
-- always sends a clean username; this protects non-app account creation paths.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_username text;
BEGIN
  v_username := COALESCE(NULLIF(NEW.raw_user_meta_data->>'username', ''), split_part(NEW.email, '@', 1));
  -- Strip disallowed chars, pad short names, cap at 20 to satisfy the CHECK.
  v_username := left(regexp_replace(v_username, '[^a-zA-Z0-9_]', '', 'g'), 20);
  IF length(v_username) < 3 THEN v_username := rpad(coalesce(v_username,'p'), 3, '0'); END IF;
  -- If the (deterministic) name is taken by someone else, salt it to stay unique.
  IF EXISTS (SELECT 1 FROM public.profiles WHERE username = v_username AND id <> NEW.id) THEN
    v_username := left(v_username, 14) || '_' || substr(md5(NEW.id::text), 1, 5);
  END IF;
  INSERT INTO public.profiles (id, username, display_name)
  VALUES (
    NEW.id,
    v_username,
    COALESCE(NULLIF(NEW.raw_user_meta_data->>'display_name', ''), v_username)
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. RLS policies for profiles
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select" ON profiles;
CREATE POLICY "profiles_select" ON profiles FOR SELECT USING (true);

DROP POLICY IF EXISTS "profiles_insert" ON profiles;
CREATE POLICY "profiles_insert" ON profiles FOR INSERT WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_update" ON profiles;
CREATE POLICY "profiles_update" ON profiles FOR UPDATE USING (auth.uid() = id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. RLS policies for daily_scores
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE daily_scores ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "daily_scores_select" ON daily_scores;
CREATE POLICY "daily_scores_select" ON daily_scores FOR SELECT USING (true);

DROP POLICY IF EXISTS "daily_scores_insert" ON daily_scores;
CREATE POLICY "daily_scores_insert" ON daily_scores FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "daily_scores_update" ON daily_scores;
CREATE POLICY "daily_scores_update" ON daily_scores FOR UPDATE USING (auth.uid() = user_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Backfill: create missing profiles for existing users who have none
--    (safe to run multiple times thanks to ON CONFLICT DO NOTHING)
-- ─────────────────────────────────────────────────────────────────────────────
INSERT INTO public.profiles (id, username, display_name)
SELECT
  u.id,
  COALESCE(NULLIF(u.raw_user_meta_data->>'username', ''), split_part(u.email, '@', 1)),
  COALESCE(NULLIF(u.raw_user_meta_data->>'display_name', ''), split_part(u.email, '@', 1))
FROM auth.users u
LEFT JOIN public.profiles p ON p.id = u.id
WHERE p.id IS NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. TOKEN SHOP: spend_tokens RPC (required for the in-app Token Shop)
--    Atomic spend: the single UPDATE with `balance >= p_amount` means the
--    wallet can never go negative, even under concurrent purchases.
--    Signed-in users only (anon EXECUTE revoked).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.spend_tokens(p_amount integer, p_reason text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_new_balance integer;
BEGIN
  IF v_uid IS NULL THEN
    RAISE EXCEPTION 'not signed in';
  END IF;
  IF p_amount IS NULL OR p_amount <= 0 THEN
    RAISE EXCEPTION 'invalid amount';
  END IF;

  UPDATE public.wallets
     SET balance = balance - p_amount, updated_at = now()
   WHERE user_id = v_uid AND balance >= p_amount
   RETURNING balance INTO v_new_balance;

  IF v_new_balance IS NULL THEN
    RAISE EXCEPTION 'insufficient balance';
  END IF;

  INSERT INTO public.token_transactions (user_id, amount, reason)
  VALUES (v_uid, -p_amount, p_reason);

  RETURN v_new_balance;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.spend_tokens(integer, text) FROM anon;
GRANT EXECUTE ON FUNCTION public.spend_tokens(integer, text) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 7. ACCOUNT-LEVEL INVENTORY: power-ups follow the account across devices.
--    buy_item atomically charges the wallet AND grants the item (one
--    transaction — coins can't be spent without receiving the item).
--    use_item atomically consumes one; CHECKs keep counts non-negative.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.inventories (
  user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  hint integer NOT NULL DEFAULT 0 CHECK (hint >= 0),
  xray integer NOT NULL DEFAULT 0 CHECK (xray >= 0),
  updated_at timestamptz DEFAULT now()
);
ALTER TABLE public.inventories ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "inventories_select" ON public.inventories;
CREATE POLICY "inventories_select" ON public.inventories FOR SELECT USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.buy_item(p_item text, p_price integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_new_balance integer;
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray') THEN RAISE EXCEPTION 'unknown item'; END IF;
  IF p_price IS NULL OR p_price < 0 THEN RAISE EXCEPTION 'invalid price'; END IF;

  IF p_price > 0 THEN
    UPDATE public.wallets
       SET balance = balance - p_price, updated_at = now()
     WHERE user_id = v_uid AND balance >= p_price
     RETURNING balance INTO v_new_balance;
    IF v_new_balance IS NULL THEN RAISE EXCEPTION 'insufficient balance'; END IF;
    -- Reason must be UNIQUE per purchase: token_transactions enforces one row
    -- per (user, reason) for idempotent grants, so a repeated 'buy-hint' would
    -- reject every purchase after the first.
    INSERT INTO public.token_transactions (user_id, amount, reason)
    VALUES (v_uid, -p_price, 'buy-' || p_item || '-' || gen_random_uuid());
  END IF;

  INSERT INTO public.inventories (user_id, hint, xray)
  VALUES (v_uid,
          CASE WHEN p_item = 'hint' THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'xray' THEN 1 ELSE 0 END)
  ON CONFLICT (user_id) DO UPDATE SET
    hint = inventories.hint + CASE WHEN p_item = 'hint' THEN 1 ELSE 0 END,
    xray = inventories.xray + CASE WHEN p_item = 'xray' THEN 1 ELSE 0 END,
    updated_at = now();

  SELECT CASE WHEN p_item = 'hint' THEN hint ELSE xray END
    INTO v_count FROM public.inventories WHERE user_id = v_uid;
  RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.use_item(p_item text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray') THEN RAISE EXCEPTION 'unknown item'; END IF;

  IF p_item = 'hint' THEN
    UPDATE public.inventories SET hint = hint - 1, updated_at = now()
     WHERE user_id = v_uid AND hint >= 1 RETURNING hint INTO v_count;
  ELSE
    UPDATE public.inventories SET xray = xray - 1, updated_at = now()
     WHERE user_id = v_uid AND xray >= 1 RETURNING xray INTO v_count;
  END IF;

  IF v_count IS NULL THEN RAISE EXCEPTION 'none left'; END IF;
  RETURN v_count;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.buy_item(text, integer) FROM anon;
GRANT EXECUTE ON FUNCTION public.buy_item(text, integer) TO authenticated;
REVOKE EXECUTE ON FUNCTION public.use_item(text) FROM anon;
GRANT EXECUTE ON FUNCTION public.use_item(text) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 8. STREAK FREEZE: adds a third inventory item. Adds the column and teaches
--    buy_item / use_item about 'freeze'. Safe to run on top of section 7.
--    NOTE: the column is `freezes` (plural) because FREEZE is a reserved
--    keyword in PostgreSQL and can't be a plain column name. The item KEY
--    passed from the app is still 'freeze'.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.inventories
  ADD COLUMN IF NOT EXISTS freezes integer NOT NULL DEFAULT 0 CHECK (freezes >= 0);

CREATE OR REPLACE FUNCTION public.buy_item(p_item text, p_price integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_new_balance integer;
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze') THEN RAISE EXCEPTION 'unknown item'; END IF;
  IF p_price IS NULL OR p_price < 0 THEN RAISE EXCEPTION 'invalid price'; END IF;

  IF p_price > 0 THEN
    UPDATE public.wallets
       SET balance = balance - p_price, updated_at = now()
     WHERE user_id = v_uid AND balance >= p_price
     RETURNING balance INTO v_new_balance;
    IF v_new_balance IS NULL THEN RAISE EXCEPTION 'insufficient balance'; END IF;
    INSERT INTO public.token_transactions (user_id, amount, reason)
    VALUES (v_uid, -p_price, 'buy-' || p_item || '-' || gen_random_uuid());
  END IF;

  INSERT INTO public.inventories (user_id, hint, xray, freezes)
  VALUES (v_uid,
          CASE WHEN p_item = 'hint'   THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'xray'   THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'freeze' THEN 1 ELSE 0 END)
  ON CONFLICT (user_id) DO UPDATE SET
    hint    = inventories.hint    + CASE WHEN p_item = 'hint'   THEN 1 ELSE 0 END,
    xray    = inventories.xray    + CASE WHEN p_item = 'xray'   THEN 1 ELSE 0 END,
    freezes = inventories.freezes + CASE WHEN p_item = 'freeze' THEN 1 ELSE 0 END,
    updated_at = now();

  SELECT CASE p_item WHEN 'hint' THEN hint WHEN 'xray' THEN xray ELSE freezes END
    INTO v_count FROM public.inventories WHERE user_id = v_uid;
  RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.use_item(p_item text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze') THEN RAISE EXCEPTION 'unknown item'; END IF;

  IF p_item = 'hint' THEN
    UPDATE public.inventories SET hint = hint - 1, updated_at = now()
     WHERE user_id = v_uid AND hint >= 1 RETURNING hint INTO v_count;
  ELSIF p_item = 'xray' THEN
    UPDATE public.inventories SET xray = xray - 1, updated_at = now()
     WHERE user_id = v_uid AND xray >= 1 RETURNING xray INTO v_count;
  ELSE
    UPDATE public.inventories SET freezes = freezes - 1, updated_at = now()
     WHERE user_id = v_uid AND freezes >= 1 RETURNING freezes INTO v_count;
  END IF;

  IF v_count IS NULL THEN RAISE EXCEPTION 'none left'; END IF;
  RETURN v_count;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 9. REAL-MONEY TOKEN PURCHASES (Stripe): server-side credit function.
--    Called ONLY by the stripe-webhook edge function (service role) after a
--    payment is verified. Idempotent via a unique (user_id, reason) — the
--    reason is 'stripe-<checkout_session_id>', so a re-delivered webhook can
--    never double-credit. Not callable by anon/authenticated clients.
-- ─────────────────────────────────────────────────────────────────────────────

-- Ensure the idempotency key exists (safe if already present).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'token_transactions_user_id_reason_key'
  ) THEN
    ALTER TABLE public.token_transactions
      ADD CONSTRAINT token_transactions_user_id_reason_key UNIQUE (user_id, reason);
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.credit_tokens(p_user_id uuid, p_amount integer, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF p_amount IS NULL OR p_amount <= 0 THEN RAISE EXCEPTION 'invalid amount'; END IF;

  INSERT INTO public.token_transactions (user_id, amount, reason)
  VALUES (p_user_id, p_amount, p_reason)
  ON CONFLICT (user_id, reason) DO NOTHING;

  IF NOT FOUND THEN RETURN; END IF; -- already credited for this payment

  INSERT INTO public.wallets (user_id, balance)
  VALUES (p_user_id, p_amount)
  ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + p_amount, updated_at = now();
END;
$$;

REVOKE EXECUTE ON FUNCTION public.credit_tokens(uuid, integer, text) FROM anon, authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 10. PUSH NOTIFICATIONS: store each device's web-push subscription.
--     The client upserts its own row (on the unique endpoint); the
--     send-reminders edge function (service role) reads them to send pushes.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.push_subscriptions (
  endpoint text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  p256dh text NOT NULL,
  auth text NOT NULL,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE public.push_subscriptions ENABLE ROW LEVEL SECURITY;

-- Owners manage their own subscriptions; the service role (edge function) bypasses RLS.
DROP POLICY IF EXISTS "push_own_select" ON public.push_subscriptions;
CREATE POLICY "push_own_select" ON public.push_subscriptions FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "push_own_insert" ON public.push_subscriptions;
CREATE POLICY "push_own_insert" ON public.push_subscriptions FOR INSERT WITH CHECK (auth.uid() = user_id);
DROP POLICY IF EXISTS "push_own_update" ON public.push_subscriptions;
CREATE POLICY "push_own_update" ON public.push_subscriptions FOR UPDATE USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "push_own_delete" ON public.push_subscriptions;
CREATE POLICY "push_own_delete" ON public.push_subscriptions FOR DELETE USING (auth.uid() = user_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 11. MEGA HINT: adds a fourth inventory item. Adds the column and teaches
--     buy_item / use_item about 'megahint'. Safe to run on top of section 8.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.inventories
  ADD COLUMN IF NOT EXISTS megahint integer NOT NULL DEFAULT 0 CHECK (megahint >= 0);

CREATE OR REPLACE FUNCTION public.buy_item(p_item text, p_price integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_new_balance integer;
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze','megahint') THEN RAISE EXCEPTION 'unknown item'; END IF;
  IF p_price IS NULL OR p_price < 0 THEN RAISE EXCEPTION 'invalid price'; END IF;

  IF p_price > 0 THEN
    UPDATE public.wallets
       SET balance = balance - p_price, updated_at = now()
     WHERE user_id = v_uid AND balance >= p_price
     RETURNING balance INTO v_new_balance;
    IF v_new_balance IS NULL THEN RAISE EXCEPTION 'insufficient balance'; END IF;
    INSERT INTO public.token_transactions (user_id, amount, reason)
    VALUES (v_uid, -p_price, 'buy-' || p_item || '-' || gen_random_uuid());
  END IF;

  INSERT INTO public.inventories (user_id, hint, xray, freezes, megahint)
  VALUES (v_uid,
          CASE WHEN p_item = 'hint'     THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'xray'     THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'freeze'   THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'megahint' THEN 1 ELSE 0 END)
  ON CONFLICT (user_id) DO UPDATE SET
    hint     = inventories.hint     + CASE WHEN p_item = 'hint'     THEN 1 ELSE 0 END,
    xray     = inventories.xray     + CASE WHEN p_item = 'xray'     THEN 1 ELSE 0 END,
    freezes  = inventories.freezes  + CASE WHEN p_item = 'freeze'   THEN 1 ELSE 0 END,
    megahint = inventories.megahint + CASE WHEN p_item = 'megahint' THEN 1 ELSE 0 END,
    updated_at = now();

  SELECT CASE p_item WHEN 'hint' THEN hint WHEN 'xray' THEN xray WHEN 'freeze' THEN freezes ELSE megahint END
    INTO v_count FROM public.inventories WHERE user_id = v_uid;
  RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.use_item(p_item text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze','megahint') THEN RAISE EXCEPTION 'unknown item'; END IF;

  IF p_item = 'hint' THEN
    UPDATE public.inventories SET hint = hint - 1, updated_at = now()
     WHERE user_id = v_uid AND hint >= 1 RETURNING hint INTO v_count;
  ELSIF p_item = 'xray' THEN
    UPDATE public.inventories SET xray = xray - 1, updated_at = now()
     WHERE user_id = v_uid AND xray >= 1 RETURNING xray INTO v_count;
  ELSIF p_item = 'freeze' THEN
    UPDATE public.inventories SET freezes = freezes - 1, updated_at = now()
     WHERE user_id = v_uid AND freezes >= 1 RETURNING freezes INTO v_count;
  ELSE
    UPDATE public.inventories SET megahint = megahint - 1, updated_at = now()
     WHERE user_id = v_uid AND megahint >= 1 RETURNING megahint INTO v_count;
  END IF;

  IF v_count IS NULL THEN RAISE EXCEPTION 'none left'; END IF;
  RETURN v_count;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 12. PROMO CODES: redeem a code for coins. Codes + values live server-side
--     (promo_codes table, RLS-locked so clients can't read it); redeem_code
--     validates and credits, once per (user, code). Seeds a testing code.
-- ─────────────────────────────────────────────────────────────────────────────

-- Idempotency key (also created in section 9; safe if already present).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'token_transactions_user_id_reason_key') THEN
    ALTER TABLE public.token_transactions
      ADD CONSTRAINT token_transactions_user_id_reason_key UNIQUE (user_id, reason);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.promo_codes (
  code   text PRIMARY KEY,
  tokens integer NOT NULL CHECK (tokens > 0),
  active boolean NOT NULL DEFAULT true
);
ALTER TABLE public.promo_codes ENABLE ROW LEVEL SECURITY;
-- No policies: clients can't read the codes. redeem_code (SECURITY DEFINER) can.
-- `reusable` = a code that can be redeemed repeatedly (e.g. an open testing code).
ALTER TABLE public.promo_codes
  ADD COLUMN IF NOT EXISTS reusable boolean NOT NULL DEFAULT false;

-- Testing code — open/reusable so it can be redeemed over and over:
INSERT INTO public.promo_codes (code, tokens, reusable) VALUES ('moneyplease', 1000, true)
  ON CONFLICT (code) DO UPDATE SET tokens = EXCLUDED.tokens, reusable = EXCLUDED.reusable;

CREATE OR REPLACE FUNCTION public.redeem_code(p_code text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_code text := lower(trim(p_code));
  v_tokens integer;
  v_reusable boolean;
  v_reason text;
  v_new_balance integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;

  SELECT tokens, reusable INTO v_tokens, v_reusable FROM public.promo_codes WHERE code = v_code AND active;
  IF v_tokens IS NULL THEN RAISE EXCEPTION 'invalid code'; END IF;

  -- Reusable codes get a unique reason each time (always credit); one-shot codes
  -- use a fixed reason so the (user, reason) key blocks a second redemption.
  v_reason := 'promo-' || v_code || CASE WHEN v_reusable THEN '-' || gen_random_uuid() ELSE '' END;

  INSERT INTO public.token_transactions (user_id, amount, reason)
  VALUES (v_uid, v_tokens, v_reason)
  ON CONFLICT (user_id, reason) DO NOTHING;
  IF NOT FOUND THEN RAISE EXCEPTION 'already redeemed'; END IF;

  INSERT INTO public.wallets (user_id, balance) VALUES (v_uid, v_tokens)
  ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + v_tokens, updated_at = now()
  RETURNING balance INTO v_new_balance;

  RETURN v_new_balance;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.redeem_code(text) FROM anon;
GRANT EXECUTE ON FUNCTION public.redeem_code(text) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 13. CAREER POINTS: account-level progression for the Rewards track. A running
--     lifetime-score total that unlocks cosmetics by playing. Stored per user so
--     it follows the account across devices. add_career_points increments it and
--     returns the new total; clients read their own row directly (RLS-scoped).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.player_progress (
  user_id       uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  career_points bigint NOT NULL DEFAULT 0,
  updated_at    timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.player_progress ENABLE ROW LEVEL SECURITY;

-- Each user may read (and only read) their own progress row. Writes go only
-- through the SECURITY DEFINER function below, so points can't be forged.
DROP POLICY IF EXISTS "read own progress" ON public.player_progress;
CREATE POLICY "read own progress" ON public.player_progress
  FOR SELECT USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.add_career_points(p_amount integer)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_total bigint;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;

  -- Non-positive amounts are a no-op that just returns the current total (lets
  -- the client use this as a "get my total" call too).
  IF p_amount IS NULL OR p_amount <= 0 THEN
    SELECT career_points INTO v_total FROM public.player_progress WHERE user_id = v_uid;
    RETURN COALESCE(v_total, 0);
  END IF;

  INSERT INTO public.player_progress (user_id, career_points)
  VALUES (v_uid, p_amount)
  ON CONFLICT (user_id) DO UPDATE
    SET career_points = player_progress.career_points + p_amount, updated_at = now()
  RETURNING career_points INTO v_total;

  RETURN v_total;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.add_career_points(integer) FROM anon;
GRANT EXECUTE ON FUNCTION public.add_career_points(integer) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 14. NO-HINTS BADGE: record power-ups used per daily score so the leaderboard
--     can flag clean (no-hint) runs. Nullable with NO default on purpose — old
--     rows stay NULL (unknown → no badge); new rows record the real count and
--     earn the badge only when helps = 0.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.daily_scores
  ADD COLUMN IF NOT EXISTS helps integer;

-- ─────────────────────────────────────────────────────────────────────────────
-- 15. OPEN ROOMS LOBBY: mark an online room "public" so it shows up in the
--     "Find an open game" list. Private rooms (default) stay code-only.
--     (rooms SELECT is already public — join-by-code reads arbitrary rooms — so
--     no policy change is needed for the lobby to list waiting public rooms.)
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.rooms
  ADD COLUMN IF NOT EXISTS is_public boolean NOT NULL DEFAULT false;

-- ─────────────────────────────────────────────────────────────────────────────
-- 16. MULTIPLAYER POWER-UPS: store the host's per-room power-up rules so guests
--     honor the same config. { hint: bool, xray: bool, perTurn: int }. Mega Hint
--     is never offered in multiplayer. (Local pass-and-play needs no DB.)
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE public.rooms
  ADD COLUMN IF NOT EXISTS settings jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ─────────────────────────────────────────────────────────────────────────────
-- 17. UNDO power-up: adds a fifth inventory item. Adds the column and teaches
--     buy_item / use_item about 'undo'. Safe to run on top of section 11.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE public.inventories
  ADD COLUMN IF NOT EXISTS undo integer NOT NULL DEFAULT 0 CHECK (undo >= 0);

CREATE OR REPLACE FUNCTION public.buy_item(p_item text, p_price integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_new_balance integer;
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze','megahint','undo') THEN RAISE EXCEPTION 'unknown item'; END IF;
  IF p_price IS NULL OR p_price < 0 THEN RAISE EXCEPTION 'invalid price'; END IF;

  IF p_price > 0 THEN
    UPDATE public.wallets
       SET balance = balance - p_price, updated_at = now()
     WHERE user_id = v_uid AND balance >= p_price
     RETURNING balance INTO v_new_balance;
    IF v_new_balance IS NULL THEN RAISE EXCEPTION 'insufficient balance'; END IF;
    INSERT INTO public.token_transactions (user_id, amount, reason)
    VALUES (v_uid, -p_price, 'buy-' || p_item || '-' || gen_random_uuid());
  END IF;

  INSERT INTO public.inventories (user_id, hint, xray, freezes, megahint, undo)
  VALUES (v_uid,
          CASE WHEN p_item = 'hint'     THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'xray'     THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'freeze'   THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'megahint' THEN 1 ELSE 0 END,
          CASE WHEN p_item = 'undo'     THEN 1 ELSE 0 END)
  ON CONFLICT (user_id) DO UPDATE SET
    hint     = inventories.hint     + CASE WHEN p_item = 'hint'     THEN 1 ELSE 0 END,
    xray     = inventories.xray     + CASE WHEN p_item = 'xray'     THEN 1 ELSE 0 END,
    freezes  = inventories.freezes  + CASE WHEN p_item = 'freeze'   THEN 1 ELSE 0 END,
    megahint = inventories.megahint + CASE WHEN p_item = 'megahint' THEN 1 ELSE 0 END,
    undo     = inventories.undo     + CASE WHEN p_item = 'undo'     THEN 1 ELSE 0 END,
    updated_at = now();

  SELECT CASE p_item
           WHEN 'hint' THEN hint WHEN 'xray' THEN xray WHEN 'freeze' THEN freezes
           WHEN 'megahint' THEN megahint ELSE undo END
    INTO v_count FROM public.inventories WHERE user_id = v_uid;
  RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.use_item(p_item text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_count integer;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze','megahint','undo') THEN RAISE EXCEPTION 'unknown item'; END IF;

  IF p_item = 'hint' THEN
    UPDATE public.inventories SET hint = hint - 1, updated_at = now()
     WHERE user_id = v_uid AND hint >= 1 RETURNING hint INTO v_count;
  ELSIF p_item = 'xray' THEN
    UPDATE public.inventories SET xray = xray - 1, updated_at = now()
     WHERE user_id = v_uid AND xray >= 1 RETURNING xray INTO v_count;
  ELSIF p_item = 'freeze' THEN
    UPDATE public.inventories SET freezes = freezes - 1, updated_at = now()
     WHERE user_id = v_uid AND freezes >= 1 RETURNING freezes INTO v_count;
  ELSIF p_item = 'megahint' THEN
    UPDATE public.inventories SET megahint = megahint - 1, updated_at = now()
     WHERE user_id = v_uid AND megahint >= 1 RETURNING megahint INTO v_count;
  ELSE
    UPDATE public.inventories SET undo = undo - 1, updated_at = now()
     WHERE user_id = v_uid AND undo >= 1 RETURNING undo INTO v_count;
  END IF;

  IF v_count IS NULL THEN RAISE EXCEPTION 'none left'; END IF;
  RETURN v_count;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 18. ADD_TOKENS (recorded from the live DB — predates this file). The core
--     earning RPC: every client-side coin grant goes through it. Idempotent per
--     (user_id, reason) so repeated grants (e.g. 'daily-<date>' retried on each
--     sign-in) can never double-credit; returns the wallet balance either way.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.add_tokens(p_amount integer, p_reason text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_user uuid := auth.uid();
  v_rows int;
  v_balance int;
BEGIN
  IF v_user IS NULL THEN RAISE EXCEPTION 'Not authenticated'; END IF;

  INSERT INTO token_transactions (user_id, amount, reason)
  VALUES (v_user, p_amount, p_reason)
  ON CONFLICT (user_id, reason) DO NOTHING;

  GET DIAGNOSTICS v_rows = ROW_COUNT;

  IF v_rows = 0 THEN
    SELECT COALESCE(balance, 0) INTO v_balance FROM wallets WHERE user_id = v_user;
    RETURN COALESCE(v_balance, 0);
  END IF;

  INSERT INTO wallets (user_id, balance, updated_at)
  VALUES (v_user, p_amount, now())
  ON CONFLICT (user_id) DO UPDATE
    SET balance = wallets.balance + p_amount, updated_at = now()
  RETURNING balance INTO v_balance;

  RETURN v_balance;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────────────
-- 19. SERVER-AUTHORITATIVE ECONOMY TABLES (Phase 1 of the economy hardening pass)
--     item_prices + earn_rules are the SOLE source of truth for what a coin
--     purchase costs and what an earn event pays. Clients may READ them (the
--     shop needs prices to render) but CANNOT write them: RLS is on with a
--     SELECT-only policy AND write privileges are revoked from anon/authenticated.
--     Only migrations / service_role (which bypasses RLS) may write.
--     Seed values are copied EXACTLY from the live client constants.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS public.item_prices (
  kind       text    NOT NULL,                       -- 'powerup' | 'theme' | 'tileback'
  item_id    text    NOT NULL,
  price      integer NOT NULL CHECK (price >= 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, item_id)
);
ALTER TABLE public.item_prices ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "item_prices_read" ON public.item_prices;
CREATE POLICY "item_prices_read" ON public.item_prices FOR SELECT USING (true);
REVOKE INSERT, UPDATE, DELETE ON public.item_prices FROM anon, authenticated;

INSERT INTO public.item_prices (kind, item_id, price) VALUES
  ('powerup','hint',100), ('powerup','xray',80), ('powerup','megahint',300),
  ('powerup','undo',40),  ('powerup','freeze',100),
  ('theme','firecracker',750), ('theme','electric',700), ('theme','ruby',500), ('theme','galaxy',550),
  ('tileback','ruby',200), ('tileback','emerald',200), ('tileback','amethyst',200),
  ('tileback','tangerine',200), ('tileback','galaxy',250), ('tileback','rosegold',250),
  ('tileback','electric',400), ('tileback','neon',400), ('tileback','firecracker',450),
  ('tileback','neonpulse',400)
ON CONFLICT (kind, item_id) DO UPDATE SET price = EXCLUDED.price, updated_at = now();

--    amount = flat + floor(rate * score).  max_score = per-completion ceiling
--    (NULL = event takes no score). Over-ceiling behaviour is per-event (see the
--    clamp_over column added in section 20): daily REJECTS, solo CLAMPS. Both log.
--    Ceilings (generous, ~3x true max — the ceiling is a catastrophic-forge
--    backstop, NOT the anti-cheat mechanism, so it never false-rejects a legit
--    game): daily 10000 (4 words, true max ~3200, hard-bounded by maxTurns=16;
--    10% rate ⇒ ≤1000 coins). solo 12000 (9 words, base ~4100, bonus words not
--    turn-capped in solo; 1% rate ⇒ ≤170 coins).
CREATE TABLE IF NOT EXISTS public.earn_rules (
  event      text    PRIMARY KEY,
  flat       integer NOT NULL DEFAULT 0 CHECK (flat >= 0),
  rate       numeric NOT NULL DEFAULT 0 CHECK (rate >= 0),
  max_score  integer,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.earn_rules ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "earn_rules_read" ON public.earn_rules;
CREATE POLICY "earn_rules_read" ON public.earn_rules FOR SELECT USING (true);
REVOKE INSERT, UPDATE, DELETE ON public.earn_rules FROM anon, authenticated;

INSERT INTO public.earn_rules (event, flat, rate, max_score) VALUES
  ('signup',   100, 0,    NULL),
  ('daily',    0,   0.1,  10000),
  ('solo',     50,  0.01, 12000),
  ('nine',     40,  0,    NULL),
  ('mp_win',   50,  0,    NULL),
  ('mp_loss',  25,  0,    NULL),
  ('local_mp', 25,  0,    NULL),
  ('streak_wk1', 200, 0, NULL),
  ('streak_wk2', 450, 0, NULL),
  ('streak_wk3', 500, 0, NULL),
  ('streak_wk4', 600, 0, NULL)
ON CONFLICT (event) DO UPDATE SET flat=EXCLUDED.flat, rate=EXCLUDED.rate, max_score=EXCLUDED.max_score, updated_at=now();

INSERT INTO public.earn_rules (event, flat) VALUES
  ('ach-perfect_nohints',10000), ('ach-lucky4',5000), ('ach-all_green',250),
  ('ach-all_yellow',200), ('ach-no_wrong',100), ('ach-no_hints',75),
  ('ach-turns_4',500), ('ach-turns_6',250), ('ach-turns_8',100), ('ach-turns_10',60),
  ('ach-turns_12',40), ('ach-time_5m',100), ('ach-time_3m',300), ('ach-time_90s',600),
  ('ach-top10_daily',150), ('ach-top10_all',400), ('ach-play_daily',25),
  ('ach-play_solo',25), ('ach-play_local',25), ('ach-play_online',50),
  ('ach-win_online',150), ('ach-games_10',40), ('ach-games_50',150),
  ('ach-games_100',300), ('ach-butterfingers',50), ('ach-blank_slate',50),
  ('ach-scenic_route',40), ('ach-kitchen_sink',40)
ON CONFLICT (event) DO UPDATE SET flat=EXCLUDED.flat, updated_at=now();


-- ═══════════════════════════════════════════════════════════════════════════════
-- 20. ECONOMY HARDENING PHASE 2 — intent-only RPCs (server owns every amount)
-- ═══════════════════════════════════════════════════════════════════════════════
-- The SERVER is the sole authority on every coin amount and price. Clients send
-- INTENT ONLY (which item / earn event / reward) — never a value. Builds on the
-- section-19 tables (item_prices, earn_rules). Re-runnable (CREATE OR REPLACE /
-- IF NOT EXISTS / ON CONFLICT). No side effects on user data (DDL + seed + defs +
-- revokes). This section REVOKEs the old client-value RPCs (add_tokens /
-- spend_tokens / buy_item / add_career_points) — the client no longer calls them.

-- ── 20a. powerup_rewards: server-owned rewards-ladder power-up grants ────────
--    Seeded EXACTLY from REWARD_LADDER's power-up entries (index.html).
CREATE TABLE IF NOT EXISTS public.powerup_rewards (
  reward_id       text PRIMARY KEY,
  item            text NOT NULL,
  amount          integer NOT NULL CHECK (amount > 0),
  points_required bigint  NOT NULL CHECK (points_required >= 0)
);
ALTER TABLE public.powerup_rewards ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "powerup_rewards_read" ON public.powerup_rewards;
CREATE POLICY "powerup_rewards_read" ON public.powerup_rewards FOR SELECT USING (true);
REVOKE INSERT, UPDATE, DELETE ON public.powerup_rewards FROM anon, authenticated;
INSERT INTO public.powerup_rewards (reward_id, item, amount, points_required) VALUES
  ('p-hint1','hint',2,4500),  ('p-xray1','xray',2,15000), ('p-hint2','hint',3,32000),
  ('p-mega1','megahint',1,58000), ('p-xray2','xray',3,97000), ('p-hint3','hint',3,195000),
  ('p-mega2','megahint',2,280000)
ON CONFLICT (reward_id) DO UPDATE SET item=EXCLUDED.item, amount=EXCLUDED.amount, points_required=EXCLUDED.points_required;

-- ── 20b. earn_rules: career flag, over-ceiling mode, guest-migrate event ─────
--    adds_career : this event contributes its (effective) score to career_points
--    clamp_over  : TRUE  = clamp a too-high score to max_score (UNBOUNDED paths
--                          like solo — a legit outlier is never rejected)
--                  FALSE = reject a too-high score (HARD-BOUNDED paths like daily,
--                          capped by maxTurns=16 — >ceiling ⇒ tampering)
--    (daily max_score is seeded at 10000 in section 19; solo at 12000.)
ALTER TABLE public.earn_rules ADD COLUMN IF NOT EXISTS adds_career boolean NOT NULL DEFAULT false;
ALTER TABLE public.earn_rules ADD COLUMN IF NOT EXISTS clamp_over  boolean NOT NULL DEFAULT false;
UPDATE public.earn_rules SET adds_career = true WHERE event IN ('daily','solo');
UPDATE public.earn_rules SET clamp_over  = true WHERE event = 'solo';   -- solo unbounded -> CLAMP; daily bounded -> REJECT (default)
-- guest_migrate: one-time guest->account career transfer (no coins, adds career).
-- CAPPED + CLAMPED (not rejected) so a forged delta can't mint unlimited career
-- (career unlocks power-ups), while a legit heavy guest never loses their sign-in.
-- Ceiling 5,000,000: guests earn 0 coins, so career comes only from daily(<=10k)+
-- solo(<=12k) completions; a heavy ~2-month guest reaches ~2-3M, and the reward
-- ladder tops out at 360k career, so 5M is ~2x a heavy guest and ~14x the point
-- past which nothing new unlocks. Above 5M -> clamp to 5M and RAISE LOG.
INSERT INTO public.earn_rules (event, flat, rate, max_score, adds_career, clamp_over)
VALUES ('guest_migrate', 0, 0, 5000000, true, true)
ON CONFLICT (event) DO UPDATE SET flat=0, rate=0, max_score=5000000, adds_career=true, clamp_over=true;

-- PARK (future anti-cheat / rate-limit task — do NOT solve here): 'solo' uses a
-- per-GAME reason key (solo-<ts>), not per-day like daily-<date>, so it has no
-- repetition ceiling — unlimited solo games each pay out. It is the most
-- grind-exploitable earn path and belongs with raw-score validation +
-- streak-to-server in that later task, not this security pass.

-- ── 20c. grant_earn: the ONLY coin/career earning path ──────────────────────
--    Client sends (event, ref, score?) — never an amount. Coins AND career
--    commit under ONE shared (user_id, reason=ref) idempotency key, so a retry
--    can never grant one without the other. Over-ceiling behaviour is per-event
--    (reject vs clamp) and ALWAYS logged. When clamping, BOTH coins and career
--    use the clamped score, so clamp can't reopen the career hole.
CREATE OR REPLACE FUNCTION public.grant_earn(p_event text, p_ref text, p_score integer DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_ev text := p_event;
  v_flat int; v_rate numeric; v_max int; v_career boolean; v_clamp boolean;
  v_eff int; v_amount int; v_bal int; v_total bigint; v_rows int; v_week int;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_ref IS NULL OR length(p_ref) = 0 THEN RAISE EXCEPTION 'missing ref'; END IF;

  -- Streak weeks: FLOOR at 1 and CAP at 4 (mirrors client min(max(w,1),4)); a
  -- week<1 assertion can't resolve to a missing streak_wk0 row, week>4 -> wk4.
  IF v_ev LIKE 'streak_wk%' THEN
    v_week := NULLIF(regexp_replace(v_ev, '^streak_wk', ''), '')::int;
    IF v_week IS NOT NULL THEN v_ev := 'streak_wk' || least(greatest(v_week,1),4); END IF;
  END IF;

  SELECT flat, rate, max_score, adds_career, clamp_over
    INTO v_flat, v_rate, v_max, v_career, v_clamp
    FROM public.earn_rules WHERE event = v_ev;
  IF v_flat IS NULL THEN RAISE EXCEPTION 'unknown earn event: %', v_ev; END IF;

  v_eff := p_score;
  IF v_max IS NOT NULL THEN
    IF p_score IS NULL OR p_score < 0 THEN RAISE EXCEPTION 'score required'; END IF;
    IF p_score > v_max THEN
      RAISE LOG 'economy: OVER-CEILING grant_earn user=% event=% score=% ceiling=% mode=%',
                v_uid, v_ev, p_score, v_max, CASE WHEN v_clamp THEN 'clamp' ELSE 'reject' END;
      IF v_clamp THEN v_eff := v_max;                          -- clamp coins AND career
      ELSE RAISE EXCEPTION 'score exceeds ceiling'; END IF;    -- reject (bounded path)
    END IF;
  END IF;

  v_amount := v_flat + floor(v_rate * COALESCE(v_eff, 0))::int;

  -- Single idempotency gate for BOTH coins and career.
  INSERT INTO public.token_transactions (user_id, amount, reason)
  VALUES (v_uid, v_amount, p_ref)
  ON CONFLICT (user_id, reason) DO NOTHING;
  GET DIAGNOSTICS v_rows = ROW_COUNT;

  IF v_rows > 0 THEN                          -- fresh grant (not a replay)
    IF v_amount > 0 THEN
      INSERT INTO public.wallets (user_id, balance) VALUES (v_uid, v_amount)
      ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + v_amount, updated_at = now();
    END IF;
    IF v_career AND COALESCE(v_eff,0) > 0 THEN
      INSERT INTO public.player_progress (user_id, career_points) VALUES (v_uid, v_eff)
      ON CONFLICT (user_id) DO UPDATE SET career_points = player_progress.career_points + v_eff, updated_at = now();
    END IF;
  END IF;

  SELECT COALESCE(balance,0)       INTO v_bal   FROM public.wallets         WHERE user_id = v_uid;
  SELECT COALESCE(career_points,0) INTO v_total FROM public.player_progress WHERE user_id = v_uid;
  RETURN jsonb_build_object('balance', COALESCE(v_bal,0), 'career', COALESCE(v_total,0), 'granted', (v_rows > 0));
END;
$$;
REVOKE EXECUTE ON FUNCTION public.grant_earn(text, text, integer) FROM anon;
GRANT  EXECUTE ON FUNCTION public.grant_earn(text, text, integer) TO authenticated;

-- ── 20d. purchase_cosmetic: buy a theme/tile-back at the server price ────────
CREATE OR REPLACE FUNCTION public.purchase_cosmetic(p_kind text, p_id text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_price int; v_reason text; v_bal int;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_kind NOT IN ('theme','tileback') THEN RAISE EXCEPTION 'unknown kind'; END IF;
  SELECT price INTO v_price FROM public.item_prices WHERE kind = p_kind AND item_id = p_id;
  IF v_price IS NULL THEN RAISE EXCEPTION 'not for sale'; END IF;   -- reward/bundle-only items have no row
  v_reason := p_kind || '-' || p_id;                               -- 'theme-firecracker' / 'tileback-ruby'

  IF EXISTS (SELECT 1 FROM public.token_transactions WHERE user_id = v_uid AND reason = v_reason) THEN
    RAISE EXCEPTION 'already owned';
  END IF;

  IF v_price > 0 THEN
    UPDATE public.wallets SET balance = balance - v_price, updated_at = now()
     WHERE user_id = v_uid AND balance >= v_price RETURNING balance INTO v_bal;
    IF v_bal IS NULL THEN RAISE EXCEPTION 'insufficient balance'; END IF;
  ELSE
    SELECT balance INTO v_bal FROM public.wallets WHERE user_id = v_uid;
  END IF;

  -- UNIQUE(user_id,reason) is the race backstop; a dup here rolls back the deduct.
  INSERT INTO public.token_transactions (user_id, amount, reason) VALUES (v_uid, -v_price, v_reason);
  RETURN COALESCE(v_bal, 0);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.purchase_cosmetic(text, text) FROM anon;
GRANT  EXECUTE ON FUNCTION public.purchase_cosmetic(text, text) TO authenticated;

-- ── 20e. buy_powerup: buy a power-up at the server price ─────────────────────
CREATE OR REPLACE FUNCTION public.buy_powerup(p_item text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_price int; v_bal int; v_count int;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_item NOT IN ('hint','xray','freeze','megahint','undo') THEN RAISE EXCEPTION 'unknown item'; END IF;
  SELECT price INTO v_price FROM public.item_prices WHERE kind = 'powerup' AND item_id = p_item;
  IF v_price IS NULL THEN RAISE EXCEPTION 'not for sale'; END IF;

  IF v_price > 0 THEN
    UPDATE public.wallets SET balance = balance - v_price, updated_at = now()
     WHERE user_id = v_uid AND balance >= v_price RETURNING balance INTO v_bal;
    IF v_bal IS NULL THEN RAISE EXCEPTION 'insufficient balance'; END IF;
    INSERT INTO public.token_transactions (user_id, amount, reason)
    VALUES (v_uid, -v_price, 'buy-' || p_item || '-' || gen_random_uuid());
  END IF;

  INSERT INTO public.inventories (user_id, hint, xray, freezes, megahint, undo)
  VALUES (v_uid, CASE WHEN p_item='hint' THEN 1 ELSE 0 END, CASE WHEN p_item='xray' THEN 1 ELSE 0 END,
                 CASE WHEN p_item='freeze' THEN 1 ELSE 0 END, CASE WHEN p_item='megahint' THEN 1 ELSE 0 END,
                 CASE WHEN p_item='undo' THEN 1 ELSE 0 END)
  ON CONFLICT (user_id) DO UPDATE SET
    hint=inventories.hint+CASE WHEN p_item='hint' THEN 1 ELSE 0 END,
    xray=inventories.xray+CASE WHEN p_item='xray' THEN 1 ELSE 0 END,
    freezes=inventories.freezes+CASE WHEN p_item='freeze' THEN 1 ELSE 0 END,
    megahint=inventories.megahint+CASE WHEN p_item='megahint' THEN 1 ELSE 0 END,
    undo=inventories.undo+CASE WHEN p_item='undo' THEN 1 ELSE 0 END, updated_at=now();

  SELECT CASE p_item WHEN 'hint' THEN hint WHEN 'xray' THEN xray WHEN 'freeze' THEN freezes
                     WHEN 'megahint' THEN megahint ELSE undo END
    INTO v_count FROM public.inventories WHERE user_id = v_uid;
  RETURN v_count;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.buy_powerup(text) FROM anon;
GRANT  EXECUTE ON FUNCTION public.buy_powerup(text) TO authenticated;

-- ── 20f. claim_powerup_reward: grant a ladder power-up reward, career-verified
--    Replaces the old buy_item(...,0) free-grant path. Server checks the player
--    actually reached the career threshold. Idempotent on 'reward-<id>'.
CREATE OR REPLACE FUNCTION public.claim_powerup_reward(p_reward_id text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_item text; v_amount int; v_req bigint; v_career bigint; v_count int; v_rows int;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  SELECT item, amount, points_required INTO v_item, v_amount, v_req
    FROM public.powerup_rewards WHERE reward_id = p_reward_id;
  IF v_item IS NULL THEN RAISE EXCEPTION 'unknown reward'; END IF;

  SELECT COALESCE(career_points,0) INTO v_career FROM public.player_progress WHERE user_id = v_uid;
  IF COALESCE(v_career,0) < v_req THEN RAISE EXCEPTION 'reward not earned'; END IF;

  INSERT INTO public.token_transactions (user_id, amount, reason)
  VALUES (v_uid, 0, 'reward-' || p_reward_id)
  ON CONFLICT (user_id, reason) DO NOTHING;
  GET DIAGNOSTICS v_rows = ROW_COUNT;

  IF v_rows > 0 THEN
    INSERT INTO public.inventories (user_id, hint, xray, freezes, megahint, undo)
    VALUES (v_uid, CASE WHEN v_item='hint' THEN v_amount ELSE 0 END, CASE WHEN v_item='xray' THEN v_amount ELSE 0 END,
                   CASE WHEN v_item='freeze' THEN v_amount ELSE 0 END, CASE WHEN v_item='megahint' THEN v_amount ELSE 0 END,
                   CASE WHEN v_item='undo' THEN v_amount ELSE 0 END)
    ON CONFLICT (user_id) DO UPDATE SET
      hint=inventories.hint+CASE WHEN v_item='hint' THEN v_amount ELSE 0 END,
      xray=inventories.xray+CASE WHEN v_item='xray' THEN v_amount ELSE 0 END,
      freezes=inventories.freezes+CASE WHEN v_item='freeze' THEN v_amount ELSE 0 END,
      megahint=inventories.megahint+CASE WHEN v_item='megahint' THEN v_amount ELSE 0 END,
      undo=inventories.undo+CASE WHEN v_item='undo' THEN v_amount ELSE 0 END, updated_at=now();
  END IF;

  SELECT CASE v_item WHEN 'hint' THEN hint WHEN 'xray' THEN xray WHEN 'freeze' THEN freezes
                     WHEN 'megahint' THEN megahint ELSE undo END
    INTO v_count FROM public.inventories WHERE user_id = v_uid;
  RETURN COALESCE(v_count, 0);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.claim_powerup_reward(text) FROM anon;
GRANT  EXECUTE ON FUNCTION public.claim_powerup_reward(text) TO authenticated;

-- ── 20g. Lock down the OLD client-value RPCs (the actual exploit surface) ────
--    They trusted a client amount/price. No client path may call them anymore.
--    credit_tokens (service-role, Stripe webhook) and redeem_code/use_item
--    (already safe) are untouched. add_career_points writes are killed; the
--    client reads career via a plain SELECT on player_progress (RLS read-own).
--    FUTURE: multiplayer->career MUST route through grant_earn (an 'mp_*'/sibling
--    earn event with adds_career), NEVER by re-granting execute on add_career_points.
--    NOTE: must revoke from PUBLIC, not just anon/authenticated — CREATE FUNCTION
--    grants EXECUTE to PUBLIC by default, and authenticated inherits it THROUGH
--    PUBLIC, so `REVOKE ... FROM anon, authenticated` alone leaves the function
--    callable (verified by the tamper suite: add_tokens/buy_item/add_career_points
--    were still reachable until PUBLIC was revoked).
REVOKE EXECUTE ON FUNCTION public.add_tokens(integer, text)     FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.spend_tokens(integer, text)   FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.buy_item(text, integer)       FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.add_career_points(integer)    FROM PUBLIC, anon, authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 21. LEADERBOARD ARCHIVE. A safety net for score history, plus the record of one
--     reset that was applied and then deliberately rolled back.
--
--     2026-07-31: the scoring formula changed twice in a day (power-up use now
--     costs HELP_PENALTY, and a spare guess went 50 -> SPARE_GUESS_PTS=100), and
--     the Jul 30 anagram quad had scored correctly-ordered words yellow. Scores
--     from before those fixes aren't strictly comparable with scores after, so
--     133 rows (10 players, Jun 17 - Jul 30) were archived and daily_scores was
--     emptied. Coins (wallets), career (player_progress), inventories and
--     achievements were NOT touched.
--
--     Same day, that call was reversed: all 133 rows were restored from the
--     archive (verified — row count, sum(score)=257132 and a full EXCEPT check
--     all matched). LIVE STATE IS "HISTORY INTACT"; nothing is currently wiped.
--     The archive rows were kept as a backup rather than deleted.
--
--     Known and accepted: the leaderboard now spans three scoring eras. Five
--     archived rows score above 2400, which is impossible under the formula that
--     immediately preceded the change and is the fingerprint of an older
--     wrongGuesses-based "accuracy" bonus (ceiling ~2600). Current max is 3000,
--     so older entries sit on a lower ceiling and drift down All Time over time.
--
--     This table is server-side only: RLS on with no policies and all grants
--     revoked, so neither anon nor authenticated can read it. Reach it through
--     the SQL editor / service role.
CREATE TABLE IF NOT EXISTS public.daily_scores_archive
  (LIKE public.daily_scores INCLUDING DEFAULTS);

ALTER TABLE public.daily_scores_archive
  ADD COLUMN IF NOT EXISTS archived_at    timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS archive_reason text;

ALTER TABLE public.daily_scores_archive ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.daily_scores_archive FROM anon, authenticated;

-- To reset again later, run these two together (archive FIRST, and verify the
-- copy before deleting — DELETE itself has no undo; the archive IS the undo):
--   INSERT INTO public.daily_scores_archive
--     SELECT d.*, now(), '<why>' FROM public.daily_scores d;
--   DELETE FROM public.daily_scores;
--
-- To restore from the archive (this exact statement was used on 2026-07-31).
-- The column list must be explicit — the archive carries two extra columns, so
-- `SELECT *` will not line up. ON CONFLICT protects any score posted since the
-- wipe from being clobbered by an older archived row:
--   INSERT INTO public.daily_scores
--     (id, user_id, score, day_key, turns, elapsed, wrong_guesses, blocks, created_at, helps)
--   SELECT id, user_id, score, day_key, turns, elapsed, wrong_guesses, blocks, created_at, helps
--     FROM public.daily_scores_archive
--    ON CONFLICT (user_id, day_key) DO NOTHING;

-- ─────────────────────────────────────────────────────────────────────────────
-- §22  FRIENDS (social graph)                                          2026-08-09
-- ─────────────────────────────────────────────────────────────────────────────
-- A mutual friendship graph: one row per pair, direction-agnostic. `requester`
-- and `addressee` record WHO asked; `user_low`/`user_high` (sorted uuids) give a
-- single UNIQUE key so a pair can never be duplicated regardless of who sent the
-- request. `status` is 'pending' until the addressee accepts, then 'accepted'.
--
-- Security model mirrors §20's economy RPCs: SELECT is allowed (either party may
-- read rows involving them) but ALL WRITES go through SECURITY DEFINER RPCs that
-- enforce auth.uid() — the client never writes the table directly and never sends
-- relationship state, only intent (a username / a target id). Each function is
-- REVOKEd from PUBLIC and GRANTed to authenticated. Revoking from PUBLIC (not just
-- anon) is REQUIRED: CREATE FUNCTION grants EXECUTE to PUBLIC by default, and anon
-- inherits that via PUBLIC, so `REVOKE … FROM anon` alone leaves anon able to call
-- it. (Even then the auth.uid() NULL guard makes an anon call a harmless
-- 'not signed in' — but locking it at the grant layer is the house convention.)

CREATE TABLE IF NOT EXISTS public.friendships (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requester  uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  addressee  uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  status     text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted')),
  user_low   uuid GENERATED ALWAYS AS (LEAST(requester, addressee))    STORED,
  user_high  uuid GENERATED ALWAYS AS (GREATEST(requester, addressee)) STORED,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT friendships_no_self CHECK (requester <> addressee),
  CONSTRAINT friendships_unique_pair UNIQUE (user_low, user_high)
);
CREATE INDEX IF NOT EXISTS friendships_requester_idx ON public.friendships (requester);
CREATE INDEX IF NOT EXISTS friendships_addressee_idx ON public.friendships (addressee);

ALTER TABLE public.friendships ENABLE ROW LEVEL SECURITY;
-- Either party may READ a row that involves them. No INSERT/UPDATE/DELETE policy:
-- writes are the RPCs' job (SECURITY DEFINER bypasses RLS), so leaving them out
-- means a direct client write is denied by default.
DROP POLICY IF EXISTS "read own friendships" ON public.friendships;
CREATE POLICY "read own friendships" ON public.friendships FOR SELECT
  USING (auth.uid() = requester OR auth.uid() = addressee);

-- send_friend_request(p_username): create a pending request to the named user.
-- If they already sent ME a pending one, accept it instead (mutual intent). If a
-- relationship already exists, return its current status without erroring.
-- Returns jsonb { status: 'pending' | 'accepted' }.
CREATE OR REPLACE FUNCTION public.send_friend_request(p_username text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid    uuid := auth.uid();
  v_target uuid;
  v_row    public.friendships%ROWTYPE;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_username IS NULL OR length(trim(p_username)) = 0 THEN RAISE EXCEPTION 'missing username'; END IF;

  SELECT id INTO v_target FROM public.profiles
    WHERE lower(username) = lower(trim(p_username)) LIMIT 1;
  IF v_target IS NULL THEN RAISE EXCEPTION 'user not found'; END IF;
  IF v_target = v_uid  THEN RAISE EXCEPTION 'cannot add yourself'; END IF;

  SELECT * INTO v_row FROM public.friendships
    WHERE user_low = LEAST(v_uid, v_target) AND user_high = GREATEST(v_uid, v_target);

  IF FOUND THEN
    IF v_row.status = 'accepted' THEN
      RETURN jsonb_build_object('status', 'accepted');
    END IF;
    -- Pending already. If THEY asked ME, this call is an acceptance.
    IF v_row.requester = v_target THEN
      UPDATE public.friendships SET status = 'accepted' WHERE id = v_row.id;
      RETURN jsonb_build_object('status', 'accepted');
    END IF;
    -- I already asked them — still pending.
    RETURN jsonb_build_object('status', 'pending');
  END IF;

  INSERT INTO public.friendships (requester, addressee, status)
    VALUES (v_uid, v_target, 'pending');
  RETURN jsonb_build_object('status', 'pending');
END;
$$;
REVOKE EXECUTE ON FUNCTION public.send_friend_request(text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.send_friend_request(text) TO authenticated;

-- respond_friend_request(p_requester, p_accept): the ADDRESSEE accepts or
-- declines a pending request. Only rows where I am the addressee are touched, so
-- a caller can't accept a request that wasn't sent to them.
CREATE OR REPLACE FUNCTION public.respond_friend_request(p_requester uuid, p_accept boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_accept THEN
    UPDATE public.friendships SET status = 'accepted'
      WHERE requester = p_requester AND addressee = v_uid AND status = 'pending';
  ELSE
    DELETE FROM public.friendships
      WHERE requester = p_requester AND addressee = v_uid AND status = 'pending';
  END IF;
  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.respond_friend_request(uuid, boolean) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.respond_friend_request(uuid, boolean) TO authenticated;

-- remove_friend(p_other): delete the pair with p_other — works for either party
-- and for either state, so it doubles as "cancel my outgoing request". No-op if
-- no such pair exists.
CREATE OR REPLACE FUNCTION public.remove_friend(p_other uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  DELETE FROM public.friendships
    WHERE user_low = LEAST(v_uid, p_other) AND user_high = GREATEST(v_uid, p_other);
  RETURN jsonb_build_object('ok', true);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.remove_friend(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.remove_friend(uuid) TO authenticated;

-- list_friends(): one call for the whole Friends screen. Returns jsonb with
-- three arrays of { id, username, display_name }:
--   friends  — accepted, the other party in each of my accepted pairs
--   incoming — pending requests sent TO me (I am the addressee)
--   outgoing — pending requests I sent (I am the requester)
CREATE OR REPLACE FUNCTION public.list_friends()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid      uuid := auth.uid();
  v_friends  jsonb;
  v_incoming jsonb;
  v_outgoing jsonb;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'id', p.id, 'username', p.username, 'display_name', p.display_name
         ) ORDER BY p.username), '[]'::jsonb)
    INTO v_friends
    FROM public.friendships f
    JOIN public.profiles p
      ON p.id = CASE WHEN f.requester = v_uid THEN f.addressee ELSE f.requester END
   WHERE f.status = 'accepted' AND (f.requester = v_uid OR f.addressee = v_uid);

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'id', p.id, 'username', p.username, 'display_name', p.display_name
         ) ORDER BY p.username), '[]'::jsonb)
    INTO v_incoming
    FROM public.friendships f
    JOIN public.profiles p ON p.id = f.requester
   WHERE f.status = 'pending' AND f.addressee = v_uid;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'id', p.id, 'username', p.username, 'display_name', p.display_name
         ) ORDER BY p.username), '[]'::jsonb)
    INTO v_outgoing
    FROM public.friendships f
    JOIN public.profiles p ON p.id = f.addressee
   WHERE f.status = 'pending' AND f.requester = v_uid;

  RETURN jsonb_build_object('friends', v_friends, 'incoming', v_incoming, 'outgoing', v_outgoing);
END;
$$;
REVOKE EXECUTE ON FUNCTION public.list_friends() FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.list_friends() TO authenticated;
