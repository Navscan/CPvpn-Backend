// routes/voucher.js — v2.2.0
// Enterprise Voucher Generation & Redemption (1 Key = 1 Email)

import { Router } from 'express';
import crypto from 'node:crypto';
import { requireAuth } from '../lib/auth.js';
import { users, getDb } from '../lib/db.js';

const router = Router();

// ---------------------------------------------------------------
// 1. Generate Voucher (Bound to the user's email)
// ---------------------------------------------------------------
router.post('/generate', requireAuth, async (req, res) => {
  const email = req.user.email;

  try {
    const db = getDb();
    const vouchers = db.collection('enterprise_vouchers');
    
    // Generate a secure 16-character hex string (e.g., A1B2-C3D4-E5F6-G7H8)
    const rawHex = crypto.randomBytes(8).toString('hex').toUpperCase();
    const formattedCode = `${rawHex.slice(0,4)}-${rawHex.slice(4,8)}-${rawHex.slice(8,12)}-${rawHex.slice(12,16)}`;

    const voucherDoc = {
      code: formattedCode,
      bound_to: email, // <--- CRITICAL SECURITY BIND
      is_used: false,
      duration_days: 365,
      created_at: new Date()
    };

    await vouchers.insertOne(voucherDoc);

    console.log(`[VOUCHER] Generated ${formattedCode} locked to ${email}`);

    res.json({ 
      ok: true, 
      code: formattedCode,
      expires_in_days: 365
    });

  } catch (err) {
    console.error('Voucher generate error', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ---------------------------------------------------------------
// 2. Redeem Voucher (App or Web)
// ---------------------------------------------------------------
router.post('/redeem', requireAuth, async (req, res) => {
  const { code } = req.body || {};
  const email = req.user.email;

  if (!code) {
    return res.status(400).json({ ok: false, error: 'missing_code' });
  }

  // Normalize code
  const cleanCode = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const formattedCode = `${cleanCode.slice(0,4)}-${cleanCode.slice(4,8)}-${cleanCode.slice(8,12)}-${cleanCode.slice(12,16)}`;

  try {
    const db = getDb();
    const vouchers = db.collection('enterprise_vouchers');

    // 1. Verify voucher exists
    const voucher = await vouchers.findOne({ code: formattedCode });
    if (!voucher) {
      return res.status(404).json({ ok: false, error: 'voucher_not_found' });
    }

    // 2. Verify voucher belongs to THIS user
    if (voucher.bound_to && voucher.bound_to !== email) {
      console.warn(`[VOUCHER] Blocked attempt to use ${formattedCode} by ${email} (owned by ${voucher.bound_to})`);
      return res.status(403).json({ ok: false, error: 'voucher_bound_to_different_user' });
    }

    // 3. Verify voucher is not already used
    if (voucher.is_used) {
      return res.status(400).json({ ok: false, error: 'voucher_already_used' });
    }

    // 4. Mark as used (atomic update)
    const claimResult = await vouchers.updateOne(
      { _id: voucher._id, is_used: false },
      { $set: { is_used: true, used_at: new Date() } }
    );

    if (claimResult.modifiedCount === 0) {
      return res.status(400).json({ ok: false, error: 'voucher_already_claimed' });
    }

    // 5. Upgrade the user
    const days = voucher.duration_days || 365;
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + days);

    await users().updateOne(
      { email },
      { 
        $set: { 
          tier: 'enterprise', 
          is_active: true, 
          expiry_date: expiry 
        } 
      }
    );

    console.log(`[VOUCHER] User ${email} upgraded to Enterprise until ${expiry.toISOString()}`);

    res.json({ 
      ok: true, 
      tier: 'enterprise', 
      expiry_date: expiry.toISOString()
    });

  } catch (err) {
    console.error('Voucher redeem error', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

export default router;
