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
