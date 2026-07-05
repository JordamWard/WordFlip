// WordFlip — send "daily puzzle is waiting" web-push reminders.
//
// Meant to be called on a schedule (e.g. once each evening) by Supabase's cron
// (pg_cron / scheduled functions) with a shared secret header. It pushes only to
// users who have NOT completed today's Daily Challenge, and prunes dead
// subscriptions (404/410).
//
// Required secrets (set with `supabase secrets set`):
//   VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY  — your VAPID key pair (see setup doc)
//   VAPID_SUBJECT                        — a mailto:you@example.com
//   CRON_SECRET                          — any random string; the caller must send it
//   SUPABASE_SERVICE_ROLE_KEY            — auto-provided in edge functions
//
// Deploy:  supabase functions deploy send-reminders --no-verify-jwt
//
// NOTE: `web-push` is a Node library; if it doesn't run cleanly on the Deno edge
// runtime, swap it for a Deno-native web-push implementation — the surrounding
// query/prune logic stays the same.
import webpush from 'https://esm.sh/web-push@3.6.7';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0';

Deno.serve(async (req) => {
  // Only our scheduler may trigger this.
  if (req.headers.get('x-cron-secret') !== Deno.env.get('CRON_SECRET')) {
    return new Response('unauthorized', { status: 401 });
  }

  webpush.setVapidDetails(
    Deno.env.get('VAPID_SUBJECT') || 'mailto:admin@example.com',
    Deno.env.get('VAPID_PUBLIC_KEY')!,
    Deno.env.get('VAPID_PRIVATE_KEY')!,
  );

  const admin = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );

  // Today's day_key in the app's format (YYYY-M-D, no leading zeros). Uses UTC —
  // fine for an evening reminder; refine per-timezone later if needed.
  const now = new Date();
  const dayKey = `${now.getFullYear()}-${now.getMonth() + 1}-${now.getDate()}`;

  const { data: played } = await admin.from('daily_scores').select('user_id').eq('day_key', dayKey);
  const playedSet = new Set((played || []).map((r: { user_id: string }) => r.user_id));

  const { data: subs } = await admin.from('push_subscriptions').select('*');
  const payload = JSON.stringify({
    title: 'WordFlip',
    body: "Today's puzzle is waiting — keep your streak alive! 🔥",
    url: '/',
    tag: 'wordflip-daily',
  });

  let sent = 0, removed = 0;
  for (const s of (subs || [])) {
    if (playedSet.has(s.user_id)) continue; // already played today — don't nag
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        payload,
      );
      sent++;
    } catch (e) {
      const code = (e as { statusCode?: number }).statusCode;
      if (code === 404 || code === 410) { // gone — clean up
        await admin.from('push_subscriptions').delete().eq('endpoint', s.endpoint);
        removed++;
      }
    }
  }

  return new Response(JSON.stringify({ sent, removed }), {
    headers: { 'Content-Type': 'application/json' },
  });
});
