-- ═══════════════════════════════════════════════════════════════════════════════
-- PENDING (not applied). Quick win #2: lock down the score and multiplayer tables.
-- Written 2026-11-19. Apply in the Supabase SQL editor after review; see README.md.
-- ═══════════════════════════════════════════════════════════════════════════════

-- ── A. daily_scores ─────────────────────────────────────────────────────────
-- Today any signed-in player can post any score for any day, then edit it.
-- After this: insert only your own row, score 0..3,000 (the true daily max),
-- for a day within one day of today (UTC, to cover every time zone), and no
-- edits or deletes. The client already inserts with ignoreDuplicates (ON
-- CONFLICT DO NOTHING), so it never needed UPDATE.
-- Drops EVERY existing policy on the table first (the live table has
-- duplicates) and recreates the two the app uses.
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT policyname FROM pg_policies
            WHERE schemaname = 'public' AND tablename = 'daily_scores' LOOP
    EXECUTE format('DROP POLICY %I ON public.daily_scores', r.policyname);
  END LOOP;
END $$;

ALTER TABLE public.daily_scores ENABLE ROW LEVEL SECURITY;

CREATE POLICY "daily_scores_select" ON public.daily_scores
  FOR SELECT USING (true);

CREATE POLICY "daily_scores_insert" ON public.daily_scores
  FOR INSERT TO authenticated
  WITH CHECK (
    auth.uid() = user_id
    AND score BETWEEN 0 AND 3000
    AND day_key IN (
      to_char((now() AT TIME ZONE 'utc')::date - 1, 'FMYYYY-FMMM-FMDD'),
      to_char((now() AT TIME ZONE 'utc')::date,     'FMYYYY-FMMM-FMDD'),
      to_char((now() AT TIME ZONE 'utc')::date + 1, 'FMYYYY-FMMM-FMDD')
    )
  );

REVOKE UPDATE, DELETE, TRUNCATE ON public.daily_scores FROM anon, authenticated;
REVOKE INSERT ON public.daily_scores FROM anon;

-- ── B. rooms / players / game_state (online multiplayer) ────────────────────
-- Today the rules let anyone holding the public app key change or delete any
-- room. "Only room members may write" can't be enforced in SQL alone yet:
-- online players are identified by a random id kept in the browser
-- (wf_player_id), not by a sign-in, so the database can't tell who is a
-- member. That needs a client change (Supabase anonymous sign-in, or a
-- per-player secret checked by an RPC) and is left for a follow-up.
--
-- What this does now, with no client change:
--   * nobody can DELETE a room or a game_state row (the app never does)
--   * a finished room can't be reopened or edited
--   * a room's words, code, seed and host can't be changed after creation
--     (column-level UPDATE: only status, started_at, is_public, settings)
--   * game_state can only change while its room is playing, and its room_id
--     can't be moved
--   * players can't join or edit a finished room; sanity limits on score,
--     name and turn order
-- Players still delete their own row on leave (by id), so DELETE on players
-- stays open.

-- Drop every existing policy on the three tables (the live ones are all "true").
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT tablename, policyname FROM pg_policies
            WHERE schemaname = 'public' AND tablename IN ('rooms','players','game_state') LOOP
    EXECUTE format('DROP POLICY %I ON public.%I', r.policyname, r.tablename);
  END LOOP;
END $$;

ALTER TABLE public.rooms      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.players    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.game_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY "rooms_select" ON public.rooms FOR SELECT USING (true);  -- join-by-code + lobby
CREATE POLICY "rooms_insert" ON public.rooms FOR INSERT WITH CHECK (status = 'waiting');
CREATE POLICY "rooms_update" ON public.rooms FOR UPDATE
  USING (status <> 'done')
  WITH CHECK (status IN ('waiting','playing','done'));
REVOKE UPDATE, DELETE, TRUNCATE ON public.rooms FROM anon, authenticated;
GRANT  UPDATE (status, started_at, is_public, settings) ON public.rooms TO anon, authenticated;

CREATE POLICY "players_select" ON public.players FOR SELECT USING (true);
CREATE POLICY "players_insert" ON public.players FOR INSERT
  WITH CHECK (EXISTS (SELECT 1 FROM public.rooms r WHERE r.id = room_id AND r.status <> 'done'));
CREATE POLICY "players_update" ON public.players FOR UPDATE
  USING (EXISTS (SELECT 1 FROM public.rooms r WHERE r.id = room_id AND r.status <> 'done'))
  WITH CHECK (EXISTS (SELECT 1 FROM public.rooms r WHERE r.id = room_id AND r.status <> 'done'));
CREATE POLICY "players_delete" ON public.players FOR DELETE USING (true);
REVOKE TRUNCATE ON public.players FROM anon, authenticated;
-- NOT VALID: checks new and changed rows only, so old rows can't block the apply.
ALTER TABLE public.players DROP CONSTRAINT IF EXISTS players_sane;
ALTER TABLE public.players ADD CONSTRAINT players_sane CHECK (
  score BETWEEN 0 AND 5000                -- 9 words x 300 = 2,700 is the real max
  AND turn_order BETWEEN 0 AND 9
  AND char_length(name) BETWEEN 1 AND 40
) NOT VALID;

CREATE POLICY "game_state_select" ON public.game_state FOR SELECT USING (true);
CREATE POLICY "game_state_insert" ON public.game_state FOR INSERT
  WITH CHECK (EXISTS (SELECT 1 FROM public.rooms r WHERE r.id = room_id AND r.status = 'playing'));
CREATE POLICY "game_state_update" ON public.game_state FOR UPDATE
  USING (EXISTS (SELECT 1 FROM public.rooms r WHERE r.id = room_id AND r.status = 'playing'))
  WITH CHECK (EXISTS (SELECT 1 FROM public.rooms r WHERE r.id = room_id AND r.status = 'playing'));
REVOKE UPDATE, DELETE, TRUNCATE ON public.game_state FROM anon, authenticated;
GRANT  UPDATE (found_words, turn_number, current_player_id, turn_started_at, turn_expires_at)
  ON public.game_state TO anon, authenticated;

-- Check after applying (read-only):
--   SELECT tablename, policyname, cmd, roles, qual, with_check
--     FROM pg_policies WHERE schemaname='public'
--      AND tablename IN ('daily_scores','rooms','players','game_state') ORDER BY 1,2;
