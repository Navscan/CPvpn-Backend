// routes/register.js — POST /api/register
// v0.1.0
//
// Contract: app sends { voucher }. Server calls TT verify, and on
// success allocates a WireGuard peer and returns a client config.
// The voucher is consumed by TT during the verify call. The
// server never stores the client's private key.

import { Router } from 'express';
import { peers } from '../lib/db.js';
import { buildFreshPeerConfig } from '../lib/configgen.js';
import { addPeer, persistPeer } from '../lib/wireguard.js';

const router = Router();

const TT_VERIFY_URL = process.env.TT_VERIFY_URL;
const TT_VERIFY_SECRET = process.env.TTVPN_VERIFY_SECRET;

if (!TT_VERIFY_URL || !TT_VERIFY_SECRET) {
  throw new Error('TT_VERIFY_URL and TTVPN_VERIFY_SECRET are required');
}

async function verifyVoucher(voucher) {
  let res;
  try {
    res = await fetch(TT_VERIFY_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-TTVPN-Secret': TT_VERIFY_SECRET,
      },
      body: JSON.stringify({ voucher }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    return { valid: false, reason: 'upstream_unreachable' };
  }

  if (res.status !== 200) {
    return { valid: false, reason: 'upstream_error' };
  }

  let body;
  try {
    body = await res.json();
  } catch {
    return { valid: false, reason: 'upstream_error' };
  }

  if (body.valid !== true) {
    return { valid: false, reason: body.reason || 'invalid' };
  }

  return {
    valid: true,
    email: body.email,
    clientCode: body.clientCode,
    subscriptionExpiresAt: body.subscriptionExpiresAt,
  };
}

router.post('/api/register', async (req, res) => {
  const voucher = typeof req.body?.voucher === 'string'
    ? req.body.voucher.trim()
    : null;

  if (!voucher) {
    return res.status(400).json({ ok: false, error: 'missing_voucher' });
  }

  const verification = await verifyVoucher(voucher);

  if (!verification.valid) {
    return res.status(200).json({
      ok: false,
      reason: verification.reason,
    });
  }

  // Voucher is valid and consumed. Allocate a peer.
  let attempt = 0;
  const MAX_ATTEMPTS = 3;

  while (attempt < MAX_ATTEMPTS) {
    attempt++;

    let fresh;
    try {
      fresh = await buildFreshPeerConfig();
    } catch (err) {
      if (String(err.message).includes('IP pool exhausted')) {
        return res.status(503).json({ ok: false, reason: 'pool_exhausted' });
      }
      throw err;
    }

    const peerDoc = {
      publicKey: fresh.publicKey,
      ip: fresh.allowedIp,
      email: verification.email,
      clientCode: verification.clientCode,
      createdAt: new Date(),
      revokedAt: null,
      lastVerifiedAt: new Date(),
    };

    try {
      await peers().insertOne(peerDoc);
    } catch (err) {
      // Duplicate key on ip means another concurrent request claimed
      // it between our allocate and insert. Retry.
      if (err.code === 11000) {
        continue;
      }
      throw err;
    }

    // Database write succeeded. Now apply to WireGuard.
    try {
      await addPeer({
        publicKey: fresh.publicKey,
        allowedIp: fresh.allowedIp,
      });
      await persistPeer({
        publicKey: fresh.publicKey,
        allowedIp: fresh.allowedIp,
      });
    } catch (err) {
      // Roll back the database entry so the state stays consistent.
      await peers().deleteOne({ publicKey: fresh.publicKey });
      throw err;
    }

    return res.status(200).json({
      ok: true,
      config: fresh.clientConfig,
      assignedIp: fresh.allowedIp,
      subscriptionExpiresAt: verification.subscriptionExpiresAt,
    });
  }

  return res.status(503).json({ ok: false, reason: 'allocation_conflict' });
});

export default router;
