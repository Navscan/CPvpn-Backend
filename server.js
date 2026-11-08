import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { connect, close } from './lib/db.js';
import registerRouter from './routes/register.js';
import notifyRouter from './routes/notify.js';
import authRouter from './routes/auth.js';
import licenseRouter from './routes/license.js';
import paymentRouter from './routes/payment.js';
import configRouter from './routes/config.js';
import voucherRouter from './routes/voucher.js';
import cerberusRouter from './routes/cerberus.js';
import { runSweep } from './jobs/sweep.js';

dotenv.config();

const PORT = parseInt(process.env.PORT || '3100', 10);
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

const app = express();
app.use(cors());
app.disable('x-powered-by');

// Capture raw body for Paystack signature verification
app.use(express.json({
  limit: '16kb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Routes
app.use('/api', registerRouter);
app.use('/api', notifyRouter);
app.use('/api/auth', authRouter);
app.use('/api/license', licenseRouter);
app.use('/api/pay', paymentRouter);
app.use('/api/config', configRouter);
app.use('/api/voucher', voucherRouter);
app.use('/api/cerberus', cerberusRouter);

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'cpvpn-saas-server', uptime: process.uptime() });
});

app.use((_req, res) => {
  res.status(404).json({ ok: false, error: 'not_found' });
});

app.use((err, _req, res, _next) => {
  console.error('unhandled error', err);
  res.status(500).json({ ok: false, error: 'internal' });
});

const SWEEP_INTERVAL_MS = 24 * 60 * 60 * 1000;
let sweepTimer = null;

function scheduleSweep() {
  if (sweepTimer) clearTimeout(sweepTimer);
  sweepTimer = setTimeout(async () => {
    try {
      await runSweep();
    } catch (err) {
      console.error('scheduled sweep failed', err);
    } finally {
      scheduleSweep();
    }
  }, SWEEP_INTERVAL_MS);
  sweepTimer.unref();
}

async function start() {
  await connect();

  const server = app.listen(PORT, '127.0.0.1', () => {
    console.log(`cpvpn-server listening on 127.0.0.1:${PORT} (log_level=${LOG_LEVEL})`);
  });

  scheduleSweep();

  const shutdown = async (signal) => {
    console.log(`received ${signal}, shutting down`);
    if (sweepTimer) clearTimeout(sweepTimer);
    server.close(async () => {
      try {
        await close();
      } catch (err) {
        console.error('error closing db', err);
      }
      process.exit(0);
    });
    setTimeout(() => {
      console.error('forced exit after timeout');
      process.exit(1);
    }, 10000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

start().catch((err) => {
  console.error('startup failed', err);
  process.exit(1);
});
