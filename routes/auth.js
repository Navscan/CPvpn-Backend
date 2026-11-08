import { Router } from 'express';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { users } from '../lib/db.js';
import { generateToken } from '../lib/auth.js';

const router = Router();

// =====================================================================
// 1. PASSWORD VALIDATION & SECURITY HELPERS
// =====================================================================

const COMMON_PASSWORDS = new Set([
  'password', 'password123', '12345678', 'qwerty123', 'admin123', 
  'letmein', 'welcome1', 'iloveyou', 'monkey123', 'dragon123'
]);

function validatePasswordStrength(password) {
  if (password.length < 8) {
    return { valid: false, error: 'password_too_short', message: 'Password must be at least 8 characters.' };
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);

  if (!hasUppercase || !hasLowercase || !hasNumber || !hasSpecial) {
    return { 
      valid: false, 
      error: 'password_too_weak', 
      message: 'Password must contain an uppercase letter, a lowercase letter, a number, and a special character.' 
    };
  }

  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return { valid: false, error: 'password_too_common', message: 'This password is too common and easily guessed.' };
  }

  return { valid: true };
}

async function isPasswordPwned(password) {
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);

  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });
    const text = await response.text();
    const lines = text.split('\n');
    
    for (const line of lines) {
      const [returnedSuffix, count] = line.split(':');
      if (returnedSuffix === suffix) {
        return parseInt(count, 10); 
      }
    }
    return 0;
  } catch (err) {
    console.error('HIBP check failed', err);
    return 0; // Fail open to prevent blocking registrations if HIBP is down
  }
}

// =====================================================================
// 2. ROUTES
// =====================================================================

router.post('/register', async (req, res) => {
  const { email, password } = req.body || {};
  
  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'invalid_input', message: 'Email and password are required.' });
  }

  try {
    // Step 1: Local Complexity Check
    const strengthCheck = validatePasswordStrength(password);
    if (!strengthCheck.valid) {
      return res.status(400).json({ ok: false, error: strengthCheck.error, message: strengthCheck.message });
    }

    // Step 2: HIBP Breach Check
    const pwnedCount = await isPasswordPwned(password);
    if (pwnedCount > 0) {
      return res.status(400).json({ 
        ok: false, 
        error: 'password_breached', 
        message: `This password has appeared in ${pwnedCount} data breaches. Please choose a unique password.` 
      });
    }

    // Step 3: Database checks and creation
    const existing = await users().findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ ok: false, error: 'email_exists', message: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(password, salt);

    const newUser = {
      email: email.toLowerCase(),
      password: hash,
      tier: 'free',
      is_active: true,
      expiry_date: null,
      created_at: new Date()
    };

    const result = await users().insertOne(newUser);
    newUser._id = result.insertedId;

    const token = generateToken(newUser);
    res.status(201).json({ ok: true, token, tier: newUser.tier });

  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ ok: false, error: 'internal_error', message: 'An unexpected error occurred.' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ ok: false, error: 'missing_fields', message: 'Email and password are required.' });
  }

  try {
    const user = await users().findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(401).json({ ok: false, error: 'invalid_credentials', message: 'Invalid email or password.' });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ ok: false, error: 'invalid_credentials', message: 'Invalid email or password.' });
    }

    const token = generateToken(user);
    res.json({ ok: true, token, tier: user.tier, is_active: user.is_active });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ ok: false, error: 'internal_error', message: 'An unexpected error occurred.' });
  }
});

export default router;
