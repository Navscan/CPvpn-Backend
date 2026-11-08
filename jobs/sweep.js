// jobs/sweep.js — v2.0.0
// CPvpn SaaS expiry sweep.
//
// v2.0.0 changes:
//   - TreasureTrail (voucher) integration REMOVED. Pure SaaS.
//   - No longer throws at import if env vars are missing.
//   - Iterates cpvpn_users with tier != 'free' and expiry_date < now.
//   - Downgrades user to free, sets is_active=false,
//     then revokes all active WireGuard peers for that email.
//   - Idempotent: double-checks the tier/expiry just before writing,
//     so a concurrent renewal cannot be clobbered.
//
// Runs from server.js on a 24h timer.
// Manual invocation: node jobs/sweep.js

import { users, peers } from '../lib/db.js';
import { removePeer, unpersistPeer } from '../lib/wireguard.js';

/**
 * Revoke every active WireGuard peer for a given email.
 * Returns count of peers revoked.
 */
async function revokePeersForEmail(email, reason) {
  const activePeers = await peers().find({ email, revokedAt: null }).toArray();
  let revoked = 0;

  for (const peerDoc of activePeers) {
    const result = await peers().updateOne(
      { publicKey: peerDoc.publicKey, revokedAt: null },
      { $set: { revokedAt: new Date(), revokedReason: reason } }
    );

    if (result.modifiedCount === 0) continue;

    try {
      await removePeer(peerDoc.publicKey);
      await unpersistPeer(peerDoc.publicKey);
    } catch (err) {
      // DB mark succeeded but wg cleanup failed. Log loudly; next sweep
      // won't retry because revokedAt is already set, so this is a
      // signal for ops to intervene.
      console.error('[sweep] wg cleanup failed after DB revoke', {
        publicKey: peerDoc.publicKey,
        email,
        error: err.message,
      });
    }

    revoked++;
  }

  return revoked;
}

export async function runSweep() {
  const started = new Date();
  console.log('[sweep] started', { at: started.toISOString() });

  const now = new Date();

  let expired = [];
  try {
    expired = await users()
      .find({
        tier: { $ne: 'free' },
        expiry_date: { $ne: null, $lt: now },
      })
      .toArray();
  } catch (err) {
    console.error('[sweep] failed to query expired users', err);
    return {
      startedAt: started.toISOString(),
      durationMs: Date.now() - started.getTime(),
      scanned: 0,
      downgraded: 0,
      peersRevoked: 0,
      error: 'db_query_failed',
    };
  }

  console.log('[sweep] expired subscriptions found', { count: expired.length });

  let downgraded = 0;
  let peersRevoked = 0;

  for (const user of expired) {
    // Re-check immediately before write to avoid clobbering a concurrent renewal.
    const result = await users().updateOne(
      {
        email: user.email,
        tier: { $ne: 'free' },
        expiry_date: { $lt: now },
      },
      {
        $set: {
          tier: 'free',
          is_active: false,
          downgraded_at: now,
          downgrade_reason: 'subscription_expired',
        },
      }
    );

    if (result.modifiedCount === 0) {
      // Someone renewed between our query and our write. Skip.
      console.log('[sweep] skipped (renewed concurrently)', { email: user.email });
      continue;
    }

    downgraded++;

    const n = await revokePeersForEmail(user.email, 'subscription_expired');
    peersRevoked += n;

    console.log('[sweep] downgraded user', {
      email: user.email,
      previousTier: user.tier,
      previousExpiry: user.expiry_date,
      peersRevoked: n,
    });
  }

  const durationMs = Date.now() - started.getTime();
  const summary = {
    startedAt: started.toISOString(),
    durationMs,
    scanned: expired.length,
    downgraded,
    peersRevoked,
  };

  console.log('[sweep] complete', summary);
  return summary;
}

// Allow direct invocation: node jobs/sweep.js
if (import.meta.url === `file://${process.argv[1]}`) {
  const { connect, close } = await import('../lib/db.js');
  try {
    await connect();
    const summary = await runSweep();
    console.log(JSON.stringify(summary, null, 2));
  } catch (err) {
    console.error('[sweep] fatal', err);
    process.exitCode = 1;
  } finally {
    await close();
    process.exit();
  }
}
