# Pending database changes (not applied yet)

These three scripts fix the database items from the November 2026 review.
Nothing here runs automatically. The site keeps working the same before and
after, so they can be applied any time after the code changes in this branch
are live.

Each one was tested on a local copy of the schema (Postgres 16) with the same
calls the game makes, as a guest and as a signed-in player.

## What each script does

1. `2026-11-19_1_grant_earn_refs.sql` closes the coin farming hole.
   `grant_earn` used to trust the reference the browser sent, so a script
   could send a new reference every time and collect coins without limit
   (and `guest_migrate` could claim any career total). Now the server builds
   the reference itself: daily, nine-letter and streak rewards only for today
   (give or take a day for time zones), achievements and the signup bonus
   once each, guest career migration once per account, challenge rounds only
   for challenges you are in, and solo, local and online games capped per
   day (20 solo, 10 local, 20 online, one per online room). Reward amounts
   are unchanged.
2. `2026-11-19_2_lock_down_tables.sql` stops score and room tampering.
   `daily_scores`: anyone can read, only a signed-in player can add their own
   row, for today, with a score between 0 and 3000 (the most `scoreCalc` can
   give). Nobody can edit or delete a score from the browser.
   `rooms`, `players`, `game_state`: the game's own moves still work, but a
   finished room can't be reopened, words and seeds can't be swapped,
   rooms and game state can't be deleted, and player scores have sane limits.
   Limiting writes to the players in a room needs a client change (online
   play uses a browser-made player id, not a sign-in), so that is left for a
   later step.
3. `2026-11-19_3_function_access.sql` makes sure only the game's own
   functions can be called from the browser: every other `SECURITY DEFINER`
   function (for example `credit_tokens`, which the Stripe webhook uses) is
   limited to the server, and new functions default to not callable by the
   public.

## How to apply

1. Take a backup first (Supabase dashboard > Database > Backups), or at least
   copy the current `grant_earn` definition from the SQL editor.
2. Open the SQL editor for project `vznuengepsbnmgwfyadr` and run the files
   in order: 1, then 2, then 3. Each one is safe to run again.
3. Run the check query at the bottom of file 3. It should list only the
   game's own functions as callable by `authenticated`.
4. Play one daily, one solo game and one online game as a signed-in test
   account to confirm coins and scores still land.
5. Once applied, copy the scripts into `supabase-migrations.sql` (as new
   sections) and delete this folder, so the main file stays the record.

## Not covered by SQL

Leaked-password protection is a dashboard switch, not SQL:
Authentication > Providers > Email > "Prevent use of leaked passwords"
(needs the Pro plan).
