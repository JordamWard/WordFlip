-- WordFlip Supabase Migrations
-- Run these in the Supabase SQL editor at https://supabase.com/dashboard
-- Project: vznuengepsbnmgwfyadr
--
-- PURPOSE: Fix (1) mystery account display, (2) scores not saving to leaderboard

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. UNIQUE constraint so upsert on daily_scores(user_id, day_key) works
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE daily_scores
  ADD CONSTRAINT IF NOT EXISTS daily_scores_user_id_day_key_key
  UNIQUE (user_id, day_key);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Trigger: auto-create profile row when a new user signs up
-- ─────────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.profiles (id, username, display_name)
  VALUES (
    NEW.id,
    COALESCE(NULLIF(NEW.raw_user_meta_data->>'username', ''), split_part(NEW.email, '@', 1)),
    COALESCE(NULLIF(NEW.raw_user_meta_data->>'display_name', ''), split_part(NEW.email, '@', 1))
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
