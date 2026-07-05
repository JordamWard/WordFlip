# Daily Reminder Notifications (Web Push) — Setup

Built and shipped, but dormant until you add VAPID keys and a schedule.

## Where web push works
- **Android & desktop** (Chrome/Edge/Firefox): yes, installed or in-browser.
- **iOS 16.4+**: yes, but ONLY for the PWA **added to the home screen** (not a
  Safari tab). Users must tap "Allow" when prompted.
- Native App Store / Play builds get more reliable push later via APNs/FCM.

## What's already in the app
- **Service worker** handles incoming `push` events and notification taps.
- **Profile screen** shows a "🔔 Daily reminder" toggle — *only once
  `VAPID_PUBLIC_KEY` is set* (until then it's hidden). Toggling it asks
  permission, subscribes, and saves the subscription to `push_subscriptions`.
- **`send-reminders`** edge function pushes to everyone who hasn't finished
  today's Daily, and prunes dead subscriptions.

## One-time setup

### 1. Run the SQL
Run **section 10** of `supabase-migrations.sql` (the `push_subscriptions` table).

### 2. Generate a VAPID key pair
```
npx web-push generate-vapid-keys
```
You'll get a **public** and **private** key.

### 3. Put the PUBLIC key in the client
In `index.html`, set:
```js
const VAPID_PUBLIC_KEY = 'BJ...your public key...';
```
Commit + deploy. The reminder toggle now appears in Profile.

### 4. Set the edge-function secrets
```
supabase secrets set VAPID_PUBLIC_KEY=BJ...public...
supabase secrets set VAPID_PRIVATE_KEY=...private...
supabase secrets set VAPID_SUBJECT=mailto:you@example.com
supabase secrets set CRON_SECRET=some-long-random-string
```

### 5. Deploy the function
```
supabase functions deploy send-reminders --no-verify-jwt
```

### 6. Schedule it
In Supabase → Database → **Cron** (pg_cron), schedule a daily call, e.g. 6pm UTC:
```sql
select cron.schedule(
  'wordflip-daily-reminder',
  '0 18 * * *',
  $$
  select net.http_post(
    url    := 'https://<project-ref>.supabase.co/functions/v1/send-reminders',
    headers:= '{"x-cron-secret":"some-long-random-string"}'::jsonb
  );
  $$
);
```
(Enable the `pg_cron` and `pg_net` extensions first, under Database → Extensions.)

### 7. Test
- On an installed PWA (or Android/desktop Chrome), open Profile → toggle the
  reminder On, allow the prompt.
- Manually invoke the function to fire a test push:
```
curl -X POST 'https://<project-ref>.supabase.co/functions/v1/send-reminders' \
  -H 'x-cron-secret: some-long-random-string'
```
  You should get a notification if you haven't played today's daily.

## Notes / gotchas
- `web-push` is a Node lib; if it errors on Deno, swap it for a Deno-native
  web-push implementation — the query/prune logic around it is unchanged.
- "Today" is computed in UTC in the function; good enough for an evening nudge.
  Refine per-timezone later if you want reminders at each user's local evening.
- iOS only prompts for permission from a user gesture inside the installed PWA —
  the toggle handles that.
