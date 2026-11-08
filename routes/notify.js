// routes/notify.js — POST /api/peers/notify
// v0.1.0
//
// Inbound from TreasureTrail. TT tells us a user's subscription
// state changed, and we revoke the corresponding peers. Auth via
// X-TTVPN-Secret (TT_NOTIFY_SECRET, distinct from the outbound
// verify secret). Idempotent: revoking an already-revoked peer
// is a no-op.

import { Router } from 'express';
import { peers } from '../lib/db.js';
import { removePeer, unpersistPeer } from '../lib/wireguard.js';

const router = Router();

const NOTIFY_SECRET = process.env.TT_NOTIFY_SECRET;

if (!NOTIFY_SECRET) {
  throw new Error('TT_NOTIFY_SECRET is required');
}

const REVOKE_EVENTS = new Set([
  'subscription_expired',
  'subscription_changed',
]);

const NOOP_EVENTS = new Set([
  'subscription_activated',
]);

async function revokePeer(peerDoc) {
  // Database first, then WireGuard. If the wg command fails, the
  // peer is still marked revoked and the nightly sweep will retry.

  const result = await peers().updateOne(
    { publicKey: peerDoc.publicKey, revokedAt: null },
    { $set: { revokedAt: new Date() } }
  );

  if (result.modifiedCount === 0) {
    // Already revoked. Nothing to do.
    return false;
  }

  try {
    await removePeer(peerDoc.publicKey);
    await unpersistPeer(peerDoc.publicKey);
  } catch (err) {
    // Log and continue. The peer is marked revoked in the database,
    // which means it will be retried and will not be re-allocated.
    console.error('revoke wg command failed', {
      publicKey: peerDoc.publicKey,
      error: err.message,
    });
  }

  return true;
}

router.post('/api/peers/notify', async (req, res) => {
  const incoming = req.get('X-TTVPN-Secret');
  if (!incoming || incoming !== NOTIFY_SECRET) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }

  const { event, emails } = req.body || {};

  if (typeof event !== 'string' || !Array.isArray(emails)) {
    return res.status(400).json({
      ok: false,
      error: 'bad_request',
      detail: 'event must be a string and emails must be an array',
    });
  }

  if (emails.length === 0) {
    return res.status(200).json({
      ok: true,
      revoked: 0,
      notFound: 0,
      errors: [],
    });
  }

  if (NOOP_EVENTS.has(event)) {
    return res.status(200).json({
      ok: true,
      revoked: 0,
      notFound: 0,
      errors: [],
    });
  }

  if (!REVOKE_EVENTS.has(event)) {
    return res.status(400).json({
      ok: false,
      error: 'bad_request',
      detail: `unknown event: ${event}`,
    });
  }

  const cleanEmails = emails
    .filter(e => typeof e === 'string' && e.length > 0 && e.length <= 254)
    .map(e => e.trim().toLowerCase());

  const activePeers = await peers()
    .find({ email: { $in: cleanEmails }, revokedAt: null })
    .toArray();

  let revoked = 0;
  const errors = [];

  for (const peerDoc of activePeers) {
    try {
      const did = await revokePeer(peerDoc);
      if (did) revoked++;
    } catch (err) {
      errors.push({
        publicKey: peerDoc.publicKey,
        error: err.message,
      });
    }
  }

  const matchedEmails = new Set(activePeers.map(p => p.email));
  const notFound = cleanEmails
    .filter(e => !matchedEmails.has(e))
    .length;

  return res.status(200).json({
    ok: true,
    revoked,
    notFound,
    errors,
  });
});

export default router;
