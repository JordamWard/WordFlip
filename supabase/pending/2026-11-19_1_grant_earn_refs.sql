-- ═══════════════════════════════════════════════════════════════════════════════
-- PENDING (not applied). Quick win #1: stop coin and career farming in grant_earn.
-- Written 2026-11-19. Apply in the Supabase SQL editor after review; see README.md.
-- ═══════════════════════════════════════════════════════════════════════════════
-- The hole: grant_earn's idempotency key is the client-chosen p_ref, so a
-- signed-in player could call it again and again with fresh refs ('solo-1',
-- 'solo-2', 'daily-1999-1-1', 'career-migrate-x', ...) for unlimited coins and
-- career points.
--
-- The fix: the server decides what each event's reference may be.
--   signup              -> always 'signup-bonus' (once per account)
--   guest_migrate       -> always 'career-migrate-<your user id>' (once per account)
--   ach-<id>            -> always 'ach-<id>' (once per achievement)
--   daily / nine        -> 'daily-<date>' / 'nine-<date>', date within a day of
--                          today (UTC), so each day pays once
--   streak_wk1..4       -> 'streakwk-<date>' within a day of today, and at most
--                          one streak payout in any 6 days (milestones are 7 apart)
--   solo (friend        -> 'ch-<challenge id>-r<1..3>' only for a challenge you
--     challenge round)     are in
--   solo / local_mp     -> built by the server as '<event>-<UTC date>-<n>', capped
--                          per day (solo 20, local_mp 10). The client's own
--                          'solo-<timestamp>' ref is ignored.
--   mp_win / mp_loss    -> 'mp-<UTC date>-<room id>' (one per room), capped at 20
--                          online games a day
-- Over a daily cap the call returns granted:false with capped:true instead of
-- raising, so the client just shows no coins (no error).
--
-- Same signature, same return shape (balance, career, granted): no client change
-- needed. Amount and ceiling logic below is unchanged from section 20c.
-- Re-runnable (CREATE OR REPLACE).

CREATE OR REPLACE FUNCTION public._wf_ref_date(p_text text)
RETURNS date LANGUAGE plpgsql IMMUTABLE AS $$
-- Parses the app's unpadded 'YYYY-M-D' day key. NULL if it isn't one.
DECLARE m text[];
BEGIN
  m := regexp_match(p_text, '^(\d{4})-(\d{1,2})-(\d{1,2})$');
  IF m IS NULL THEN RETURN NULL; END IF;
  RETURN make_date(m[1]::int, m[2]::int, m[3]::int);
EXCEPTION WHEN others THEN RETURN NULL;   -- e.g. 2026-2-31
END;
$$;
REVOKE EXECUTE ON FUNCTION public._wf_ref_date(text) FROM PUBLIC, anon, authenticated;

-- Shared return value: { balance, career, granted, capped }.
CREATE OR REPLACE FUNCTION public._wf_earn_result(p_uid uuid, p_granted boolean, p_capped boolean)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_bal int; v_total bigint;
BEGIN
  SELECT COALESCE(balance,0)       INTO v_bal   FROM public.wallets         WHERE user_id = p_uid;
  SELECT COALESCE(career_points,0) INTO v_total FROM public.player_progress WHERE user_id = p_uid;
  RETURN jsonb_build_object('balance', COALESCE(v_bal,0), 'career', COALESCE(v_total,0),
                            'granted', p_granted, 'capped', p_capped);
END;
$$;
REVOKE EXECUTE ON FUNCTION public._wf_earn_result(uuid, boolean, boolean) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.grant_earn(p_event text, p_ref text, p_score integer DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_uid uuid := auth.uid();
  v_ev text := p_event;
  v_ref text;
  v_today date := (now() AT TIME ZONE 'utc')::date;
  v_daykey text := to_char((now() AT TIME ZONE 'utc')::date, 'FMYYYY-FMMM-FMDD');
  v_refdate date;
  v_cap int; v_used int; v_prefix text;
  v_m text[];
  v_flat int; v_rate numeric; v_max int; v_career boolean; v_clamp boolean;
  v_eff int; v_amount int; v_bal int; v_total bigint; v_rows int; v_week int;
BEGIN
  IF v_uid IS NULL THEN RAISE EXCEPTION 'not signed in'; END IF;
  IF p_ref IS NULL OR length(p_ref) = 0 THEN RAISE EXCEPTION 'missing ref'; END IF;

  -- Streak weeks: FLOOR at 1 and CAP at 4 (mirrors client min(max(w,1),4)).
  IF v_ev LIKE 'streak_wk%' THEN
    v_week := NULLIF(regexp_replace(v_ev, '^streak_wk', ''), '')::int;
    IF v_week IS NOT NULL THEN v_ev := 'streak_wk' || least(greatest(v_week,1),4); END IF;
  END IF;

  -- ── Server-owned reference per event ──────────────────────────────────────
  IF v_ev = 'signup' THEN
    v_ref := 'signup-bonus';

  ELSIF v_ev = 'guest_migrate' THEN
    v_ref := 'career-migrate-' || v_uid::text;

  ELSIF v_ev LIKE 'ach-%' THEN
    v_ref := v_ev;

  ELSIF v_ev IN ('daily', 'nine') THEN
    v_refdate := public._wf_ref_date(substring(p_ref from length(v_ev) + 2));
    IF left(p_ref, length(v_ev) + 1) <> v_ev || '-' OR v_refdate IS NULL
       OR v_refdate NOT BETWEEN v_today - 1 AND v_today + 1 THEN
      RAISE EXCEPTION 'bad % ref', v_ev;
    END IF;
    v_ref := v_ev || '-' || to_char(v_refdate, 'FMYYYY-FMMM-FMDD');

  ELSIF v_ev LIKE 'streak_wk%' THEN
    v_refdate := public._wf_ref_date(substring(p_ref from 10));   -- after 'streakwk-'
    IF left(p_ref, 9) <> 'streakwk-' OR v_refdate IS NULL
       OR v_refdate NOT BETWEEN v_today - 1 AND v_today + 1 THEN
      RAISE EXCEPTION 'bad streak ref';
    END IF;
    v_ref := 'streakwk-' || to_char(v_refdate, 'FMYYYY-FMMM-FMDD');
    -- One streak payout per 6 days (weekly milestones are 7 days apart).
    IF EXISTS (
      SELECT 1 FROM public.token_transactions
       WHERE user_id = v_uid AND reason LIKE 'streakwk-%' AND reason <> v_ref
         AND public._wf_ref_date(substring(reason from 10)) BETWEEN v_refdate - 6 AND v_refdate + 6
    ) THEN
      RETURN public._wf_earn_result(v_uid, false, true);
    END IF;

  ELSIF v_ev = 'solo' AND p_ref LIKE 'ch-%' THEN
    -- Friend-challenge round: 'ch-<uuid>-r<1..3>', only for a challenge you're in.
    v_m := regexp_match(p_ref, '^ch-([0-9a-f-]{36})-r([1-3])$');
    IF v_m IS NULL OR NOT EXISTS (
      SELECT 1 FROM public.challenges c
       WHERE c.id = v_m[1]::uuid AND v_uid IN (c.challenger, c.opponent)
    ) THEN
      RAISE EXCEPTION 'bad challenge ref';
    END IF;
    v_ref := 'ch-' || v_m[1] || '-r' || v_m[2];

  ELSIF v_ev IN ('solo', 'local_mp') THEN
    v_cap := CASE v_ev WHEN 'solo' THEN 20 ELSE 10 END;
    v_prefix := CASE v_ev WHEN 'solo' THEN 'solo' ELSE 'lmp' END || '-' || v_daykey || '-';
    -- Serialise this user's grants so two parallel calls can't both take slot n.
    PERFORM pg_advisory_xact_lock(hashtext('grant_earn:' || v_uid::text));
    SELECT count(*) INTO v_used FROM public.token_transactions
     WHERE user_id = v_uid AND reason LIKE v_prefix || '%';
    IF v_used >= v_cap THEN RETURN public._wf_earn_result(v_uid, false, true); END IF;
    v_ref := v_prefix || (v_used + 1);

  ELSIF v_ev IN ('mp_win', 'mp_loss') THEN
    v_m := regexp_match(p_ref, '^mp-([0-9a-f-]{36})$');
    IF v_m IS NULL THEN RAISE EXCEPTION 'bad multiplayer ref'; END IF;
    v_prefix := 'mp-' || v_daykey || '-';
    -- One payout per room, win or loss (also blocks win+loss on the same room).
    IF EXISTS (SELECT 1 FROM public.token_transactions
                WHERE user_id = v_uid AND reason LIKE 'mp-%' AND right(reason, 36) = v_m[1]) THEN
      RETURN public._wf_earn_result(v_uid, false, false);
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('grant_earn:' || v_uid::text));
    SELECT count(*) INTO v_used FROM public.token_transactions
     WHERE user_id = v_uid AND reason LIKE v_prefix || '%';
    IF v_used >= 20 THEN RETURN public._wf_earn_result(v_uid, false, true); END IF;
    v_ref := v_prefix || v_m[1];

  ELSE
    RAISE EXCEPTION 'unsupported earn event: %', v_ev;
  END IF;

  -- ── Amount (unchanged from section 20c) ───────────────────────────────────
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
      IF v_clamp THEN v_eff := v_max;
      ELSE RAISE EXCEPTION 'score exceeds ceiling'; END IF;
    END IF;
  END IF;

  v_amount := v_flat + floor(v_rate * COALESCE(v_eff, 0))::int;

  -- Single idempotency gate for BOTH coins and career, now on the server's ref.
  INSERT INTO public.token_transactions (user_id, amount, reason)
  VALUES (v_uid, v_amount, v_ref)
  ON CONFLICT (user_id, reason) DO NOTHING;
  GET DIAGNOSTICS v_rows = ROW_COUNT;

  IF v_rows > 0 THEN
    IF v_amount > 0 THEN
      INSERT INTO public.wallets (user_id, balance) VALUES (v_uid, v_amount)
      ON CONFLICT (user_id) DO UPDATE SET balance = wallets.balance + v_amount, updated_at = now();
    END IF;
    IF v_career AND COALESCE(v_eff,0) > 0 THEN
      INSERT INTO public.player_progress (user_id, career_points) VALUES (v_uid, v_eff)
      ON CONFLICT (user_id) DO UPDATE SET career_points = player_progress.career_points + v_eff, updated_at = now();
    END IF;
  END IF;

  RETURN public._wf_earn_result(v_uid, v_rows > 0, false);
END;
$$;

REVOKE EXECUTE ON FUNCTION public.grant_earn(text, text, integer) FROM PUBLIC, anon;
GRANT  EXECUTE ON FUNCTION public.grant_earn(text, text, integer) TO authenticated;

-- ── Optional, after applying: who already farmed? (read-only) ────────────────
-- Players with more than 20 solo grants on any one day, or more than one
-- guest_migrate / unusual refs, under the OLD rules:
--   SELECT user_id, count(*) AS solo_grants, sum(amount) AS coins
--     FROM public.token_transactions WHERE reason LIKE 'solo-%'
--    GROUP BY user_id ORDER BY solo_grants DESC LIMIT 20;
--   SELECT user_id, reason, amount FROM public.token_transactions
--    WHERE reason LIKE 'career-migrate-%' AND reason <> 'career-migrate-' || user_id::text;
