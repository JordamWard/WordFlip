// WordFlip — Stripe webhook: credit coins after a verified payment.
//
// Stripe calls this server-to-server. It verifies the event signature (so a
// forged request can't mint coins), then on `checkout.session.completed` reads
// the metadata set in create-checkout and credits the wallet via the
// credit_tokens RPC (idempotent on the session id). This is the ONLY place
// coins are granted for a purchase.
//
// Required secrets (set with `supabase secrets set`):
//   STRIPE_SECRET_KEY      — Stripe secret key (sk_test_… while testing)
//   STRIPE_WEBHOOK_SECRET  — the signing secret of THIS webhook endpoint (whsec_…)
//   SUPABASE_SERVICE_ROLE_KEY — auto-available in edge functions; used to call the RPC
//
// Deploy WITHOUT JWT verification (Stripe has no Supabase JWT):
//   supabase functions deploy stripe-webhook --no-verify-jwt
import Stripe from 'https://esm.sh/stripe@14.25.0?target=deno&no-check';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0';

Deno.serve(async (req) => {
  const sig = req.headers.get('stripe-signature');
  if (!sig) return new Response('missing signature', { status: 400 });

  const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!, { apiVersion: '2024-06-20' });
  const body = await req.text();

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      body, sig, Deno.env.get('STRIPE_WEBHOOK_SECRET')!,
    );
  } catch (e) {
    console.error('signature verification failed:', e);
    return new Response('bad signature', { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object as Stripe.Checkout.Session;
    const userId = s.metadata?.user_id;
    const tokens = parseInt(s.metadata?.tokens || '0', 10);
    if (userId && tokens > 0) {
      // Service-role client — bypasses RLS to call the locked-down credit RPC.
      const admin = createClient(
        Deno.env.get('SUPABASE_URL')!,
        Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
      );
      const { error } = await admin.rpc('credit_tokens', {
        p_user_id: userId,
        p_amount: tokens,
        p_reason: 'stripe-' + s.id, // idempotent: re-delivery can't double-credit
      });
      if (error) {
        console.error('credit_tokens failed:', error);
        return new Response('credit failed', { status: 500 }); // Stripe will retry
      }
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
});
