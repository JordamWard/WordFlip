-- ═══════════════════════════════════════════════════════════════════════════════
-- PENDING (not applied). Quick win #8: clear Supabase's function-access warnings.
-- Written 2026-11-19. Apply in the Supabase SQL editor after review; see README.md.
-- ═══════════════════════════════════════════════════════════════════════════════
-- CREATE FUNCTION grants EXECUTE to PUBLIC by default, and several SECURITY
-- DEFINER functions were only revoked from anon, so signed-out callers can
-- still reach them through PUBLIC. They all check auth.uid() today, so this is
-- belt and braces, but it's what the Supabase security advisor flags.
--
-- For every SECURITY DEFINER function in the public schema:
--   * revoke EXECUTE from PUBLIC and anon
--   * keep it for service_role (edge functions: credit_tokens from the Stripe
--     webhook, send-reminders)
--   * grant authenticated only the RPCs the app actually calls (list below,
--     taken from every .rpc('...') in index.html)
-- Anything else (credit_tokens, the legacy add_tokens / spend_tokens / buy_item /
-- add_career_points, trigger functions) ends up service_role only. Triggers
-- don't need EXECUTE grants to fire. Re-runnable.

DO $$
DECLARE
  f record;
  app_rpcs text[] := ARRAY[
    'buy_powerup','claim_challenge_bonus','claim_powerup_reward','create_challenge',
    'grant_earn','list_challenges','list_friends','purchase_cosmetic','redeem_code',
    'remove_friend','respond_challenge','respond_friend_request','send_friend_request',
    'submit_challenge_round','use_item'
  ];
BEGIN
  FOR f IN
    SELECT p.oid::regprocedure AS sig, p.proname
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.prosecdef
  LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon', f.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', f.sig);
    IF f.proname = ANY (app_rpcs) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', f.sig);
    ELSE
      EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM authenticated', f.sig);
    END IF;
  END LOOP;
END $$;

-- New functions should start locked too: stop handing EXECUTE to PUBLIC by default.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Check (read-only): which SECURITY DEFINER functions can anon still run? Expect none.
--   SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
--    WHERE n.nspname='public' AND p.prosecdef AND has_function_privilege('anon', p.oid, 'EXECUTE');
--
-- The other half of this quick win is a dashboard switch, not SQL:
-- Authentication > Providers > Email > "Prevent use of leaked passwords"
-- (checks new passwords against HaveIBeenPwned). Supabase offers it on the Pro
-- plan and up.
