// routes/config.js — v2.1.0
// Updated to properly remove old WireGuard peers before adding new ones.

import { Router } from 'express';
import { peers } from '../lib/db.js';
import { buildFreshPeerConfig } from '../lib/configgen.js';
import { addPeer, persistPeer, removePeer, unpersistPeer } from '../lib/wireguard.js';
import { requireAuth } from '../lib/auth.js';

const router = Router();

router.post('/provision', requireAuth, async (req, res) => {
  const email = req.user.email;
  const tier = req.user.tier || 'free';

  try {
    // 1. Revoke any existing active peers for this email
    const activePeers = await peers().find({ email, revokedAt: null }).toArray();
    for (const p of activePeers) {
      // Mark as revoked in DB
      await peers().updateOne({ _id: p._id }, { $set: { revokedAt: new Date() } });
      
      // Actually remove from WireGuard kernel and wg0.conf
      try {
        await removePeer(p.publicKey);
        await unpersistPeer(p.publicKey);
      } catch (err) {
        console.error(`Failed to cleanly remove old peer ${p.publicKey}`, err);
      }
    }

    // 2. Generate new config based on TIER
    const fresh = await buildFreshPeerConfig(tier);

    const peerDoc = {
      publicKey: fresh.publicKey,
      ip: fresh.allowedIp,
      email: email,
      createdAt: new Date(),
      revokedAt: null,
      lastVerifiedAt: new Date(),
      endpoint: fresh.metadata.endpoint
    };

    // 3. Save to Database
    await peers().insertOne(peerDoc);

    // 4. Apply to WireGuard (Kernel + Disk)
    await addPeer({ publicKey: fresh.publicKey, allowedIp: fresh.allowedIp });
    await persistPeer({ publicKey: fresh.publicKey, allowedIp: fresh.allowedIp });

    // 5. Return config + metadata to the app
    res.json({
      ok: true,
      config: fresh.clientConfig,
      assignedIp: fresh.allowedIp,
      metadata: fresh.metadata
    });

  } catch (err) {
    console.error('Provision error', err);
    res.status(500).json({ ok: false, error: 'provision_failed' });
  }
});

export default router;
