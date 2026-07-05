// WordFlip — create a Stripe Checkout Session for a coin pack.
//
// Called by the signed-in client (getSB().functions.invoke('create-checkout')).
// Verifies the user from their JWT, looks up the pack SERVER-SIDE (never trust a
// client price), creates a Stripe Checkout Session, and returns its URL. The
// actual token grant happens later in the stripe-webhook function after Stripe
// confirms payment — never here.
//
// Required secrets (set with `supabase secrets set`):
//   STRIPE_SECRET_KEY   — Stripe secret key (sk_test_… while testing)
//   APP_URL             — where to send the user back, e.g. https://wordflipgame.netlify.app
//
// Deploy:  supabase functions deploy create-checkout
import Stripe from 'https://esm.sh/stripe@14.25.0?target=deno&no-check';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0';

// The single source of truth for what each pack costs and grants.
// amount is in cents (USD). Keep ids in sync with the client's TOKEN_PACKS.
const PACKS: Record<string, { tokens: number; amount: number; name: string }> = {
  coins_500:   { tokens: 500,   amount: 99,  name: '500 Coins' },
  coins_3000:  { tokens: 3000,  amount: 399, name: '3,000 Coins' },
  coins_10000: { tokens: 10000, amount: 899, name: '10,000 Coins' },
};

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  try {
    const authHeader = req.headers.get('Authorization') || '';
    // Verify the caller with their own JWT (RLS-scoped anon client).
    const supabase = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: authHeader } } },
    );
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return json({ error: 'not signed in' }, 401);

    const { packId } = await req.json().catch(() => ({}));
    const pack = PACKS[packId];
    if (!pack) return json({ error: 'unknown pack' }, 400);

    const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!, { apiVersion: '2024-06-20' });
    const appUrl = Deno.env.get('APP_URL') || 'https://wordflipgame.netlify.app';

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: pack.name },
          unit_amount: pack.amount,
        },
        quantity: 1,
      }],
      success_url: `${appUrl}/?purchase=success`,
      cancel_url: `${appUrl}/?purchase=cancel`,
      // The webhook reads these back to know who to credit and how much.
      metadata: { user_id: user.id, tokens: String(pack.tokens), pack: packId },
    });

    return json({ url: session.url }, 200);
  } catch (e) {
    console.error('create-checkout:', e);
    return json({ error: 'checkout failed' }, 500);
  }
});

function json(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
