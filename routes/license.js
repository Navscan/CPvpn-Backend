import { Router } from 'express';
import { users } from '../lib/db.js';
import { requireAuth } from '../lib/auth.js';

const router = Router();

router.get('/check', requireAuth, async (req, res) => {
  try {
    // req.user comes from your JWT middleware in lib/auth.js
    const user = await users().findOne({ email: req.user.email });

    if (!user) {
      return res.status(404).json({ ok: false, error: 'user_not_found' });
    }

    // Check if the account is actively paid/valid
    const now = new Date();
    const isExpired = user.expiry_date && new Date(user.expiry_date) < now;
    const isActive = user.is_active && !isExpired;

    // Note: 'free' tier users might also have access, depending on your business logic.
    // If free tier gets VPN access, adjust the logic here.
    if (!isActive) {
      return res.status(403).json({ 
        ok: false, 
        error: 'subscription_inactive', 
        message: 'Your subscription has expired. Please renew to continue using CPvpn.',
        tier: user.tier,
        expiry_date: user.expiry_date
      });
    }

    res.json({ 
      ok: true, 
      active: true, 
      tier: user.tier,
      expiry_date: user.expiry_date 
    });

  } catch (err) {
    console.error('License check error', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

export default router;
