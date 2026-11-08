// routes/payment.js — v2.1.0
// Paystack integration for CPvpn SaaS.
// Added server-to-server verification to prevent spoofed webhooks.

import { Router } from 'express';
import crypto from 'node:crypto';
import { requireAuth } from '../lib/auth.js';
import { users } from '../lib/db.js';

const router = Router();
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;

const PRICES = {
  pro: 9900,        // R99.00
  enterprise: 29900 // R299.00
};

const PLAN_DAYS = 30;

// ---------------------------------------------------------------
// 1. Initiate Payment — called by the Android app
// ---------------------------------------------------------------
router.post('/initiate', requireAuth, async (req, res) => {
  const { plan } = req.body || {};
  const email = req.user.email;

  if (!plan || !PRICES[plan]) {
    return res.status(400).json({ ok: false, error: 'invalid_plan' });
  }

  if (!PAYSTACK_SECRET) {
    console.error('[pay.initiate] PAYSTACK_SECRET_KEY not set');
    return res.status(500).json({ ok: false, error: 'server_misconfigured' });
  }

  try {
    const response = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        amount: PRICES[plan],
        metadata: {
          plan,
          custom_fields: [
            { display_name: 'Plan', variable_name: 'plan', value: plan },
          ],
        },
        callback_url: 'https://api.cpvpn.store/cpvpn/api/pay/verify',
      }),
    });

    const data = await response.json();
    if (!data.status) {
      throw new Error(data.message || 'paystack_error');
    }

    res.json({ ok: true, checkout_url: data.data.authorization_url, reference: data.data.reference });
  } catch (err) {
    console.error('[pay.initiate] error', err);
    res.status(500).json({ ok: false, error: 'payment_failed' });
  }
});

// ---------------------------------------------------------------
// 2. Webhook — called by Paystack servers
//    We now VERIFY the transaction with Paystack before upgrading.
// ---------------------------------------------------------------
router.post('/webhook', async (req, res) => {
  if (!PAYSTACK_SECRET) {
    console.error('[pay.webhook] PAYSTACK_SECRET_KEY not set');
    return res.status(500).send('server_misconfigured');
  }

  // --- Signature verification (timing-safe) ---
  const expected = crypto
    .createHmac('sha512', PAYSTACK_SECRET)
    .update(req.rawBody || Buffer.alloc(0))
    .digest('hex');

  const received = (req.headers['x-paystack-signature'] || '').toString();

  let sigOk = false;
  try {
    sigOk =
      received.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(received, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    sigOk = false;
  }

  if (!sigOk) {
    console.warn('[pay.webhook] invalid signature');
    return res.status(401).send('Invalid signature');
  }

  const event = req.body || {};

  // Non-payment events: acknowledge, do nothing.
  if (event.event !== 'charge.success') {
    return res.status(200).send('ok');
  }

  const reference = event?.data?.reference;

  if (!reference) {
    console.warn('[pay.webhook] charge.success with no reference');
    return res.status(200).send('ignored_no_ref');
  }

  try {
    // --- SERVER-TO-SERVER VERIFICATION ---
    // We ignore the payload's amount/email and ask Paystack directly.
    const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
      },
    });

    const verifyData = await verifyRes.json();

    if (!verifyData.status || verifyData.data.status !== 'success') {
      console.warn(`[pay.webhook] Verification failed for ${reference}`, verifyData);
      return res.status(400).send('verification_failed');
    }

    const verifiedTx = verifyData.data;
    const email = verifiedTx.customer.email;
    const amountPaid = verifiedTx.amount; // in kobo
    const plan = verifiedTx.metadata?.plan;

    // Verify the plan matches the amount paid
    if (!plan || !PRICES[plan] || amountPaid < PRICES[plan]) {
      console.error(`[pay.webhook] Amount mismatch. Expected ${PRICES[plan]}, got ${amountPaid}`);
      return res.status(400).send('amount_mismatch');
    }

    // --- DB UPDATE ---
    const existing = await users().findOne({ email });
    if (!existing) {
      console.error('[pay.webhook] paid user not found in DB', { email });
      return res.status(200).send('user_not_found');
    }

    const now = new Date();
    const base =
      existing.expiry_date && new Date(existing.expiry_date) > now
        ? new Date(existing.expiry_date)
        : now;
    const expiry = new Date(base);
    expiry.setDate(expiry.getDate() + PLAN_DAYS);

    const result = await users().updateOne(
      { email },
      {
        $set: {
          tier: plan,
          is_active: true,
          expiry_date: expiry,
          last_payment_reference: reference,
          last_payment_at: now,
        },
      }
    );

    if (result.matchedCount === 0) {
      console.error('[pay.webhook] updateOne matched 0', { email });
      return res.status(500).send('db_no_match');
    }

    console.log(`[pay.webhook] VERIFIED & upgraded ${email} → ${plan} until ${expiry.toISOString()} (ref=${reference})`);

    return res.status(200).send('upgraded');
  } catch (err) {
    console.error('[pay.webhook] DB/Network write failed, requesting retry', err);
    return res.status(500).send('db_error');
  }
});

// ---------------------------------------------------------------
// 3. Verify — redirect target after successful Paystack checkout
// ---------------------------------------------------------------
router.get('/verify', (_req, res) => {
  res.send(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Payment Successful</title>
    <style>
      body { background:#0d0d12; color:#00ffcc; font-family:-apple-system,system-ui,sans-serif;
             text-align:center; padding:60px 20px; margin:0; }
      h1 { font-size:1.8rem; margin-bottom:0.4em; }
      p  { color:#aab; font-size:1rem; line-height:1.5; }
      .box { display:inline-block; border:1px solid #00ffcc55; padding:24px 28px;
             border-radius:14px; background:#0a0a10; max-width:420px; }
      a { color:#00ffcc; }
    </style>
  </head>
  <body>
    <div class="box">
      <h1>Payment Successful ✅</h1>
      <p>Your account has been upgraded.</p>
      <p>Close this window and return to the <strong>CPvpn</strong> app — it will sync automatically.</p>
    </div>
  </body>
</html>`);
});

export default router;
