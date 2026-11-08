// routes/cerberus.js — v1.1.0
// Enriches Fail2ban IP bans with Geolocation/ISP and serves the Live Feed.
// Now includes the /status endpoint for the Android Threat Intel tab.

import { Router } from 'express';
import os from 'node:os';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { getDb } from '../lib/db.js';

const execP = promisify(exec);
const router = Router();

// ---------------------------------------------------------------
// 1. Ingest Alert (Called by fail2ban bash script)
// ---------------------------------------------------------------
router.post('/ingest', async (req, res) => {
  const { ip, jail, action } = req.body || {};

  if (!ip || !action) {
    return res.status(400).json({ ok: false, error: 'missing_ip_or_action' });
  }

  try {
    const db = getDb();
    const logsCol = db.collection('cerberus_logs');
    const cacheCol = db.collection('ip_cache');

    let geo = { country: 'Unknown', isp: 'Unknown', flag: '🏳️' };

    if (ip !== 'SYSTEM') {
      const cachedIp = await cacheCol.findOne({ ip });
      
      if (cachedIp) {
        geo = cachedIp.geo;
      } else {
        try {
          const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,isp`);
          const data = await response.json();
          
          if (data.status === 'success') {
            geo = {
              country: data.country || 'Unknown',
              isp: data.isp || 'Unknown Host',
              flag: '🌐'
            };
            await cacheCol.insertOne({ ip, geo, cachedAt: new Date() });
          }
        } catch (e) {
          console.error('GeoIP lookup failed', e);
        }
      }
    } else {
      geo = { country: 'Local', isp: 'VPS System', flag: '💻' };
    }

    const logDoc = {
      ip,
      jail: jail || 'system',
      action,
      geo,
      timestamp: new Date()
    };

    await logsCol.insertOne(logDoc);
    
    // Keep the collection from growing infinitely
    const count = await logsCol.countDocuments();
    if (count > 500) {
      const oldest = await logsCol.find().sort({ timestamp: 1 }).limit(count - 500).toArray();
      const idsToDelete = oldest.map(doc => doc._id);
      await logsCol.deleteMany({ _id: { $in: idsToDelete } });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Ingest error', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ---------------------------------------------------------------
// 2. Fetch Logs (Called by Android App Feed)
// ---------------------------------------------------------------
router.get('/logs', async (req, res) => {
  try {
    const db = getDb();
    const logs = await db.collection('cerberus_logs')
      .find({})
      .sort({ timestamp: -1 })
      .limit(30)
      .toArray();

    res.json({ ok: true, logs });
  } catch (err) {
    console.error('Fetch logs error', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

// ---------------------------------------------------------------
// 3. Fetch Status (Called by Android App Vitals)
// ---------------------------------------------------------------
router.get('/status', async (req, res) => {
  try {
    // 1. System Vitals (Uptime, RAM)
    const uptimeSeconds = os.uptime();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memPercent = Math.round((usedMem / totalMem) * 100);

    // 2. Disk Space
    let diskPercent = 0;
    let diskTotal = 0;
    let diskUsed = 0;
    try {
      const { stdout: dfOut } = await execP('df -k / | tail -1');
      const parts = dfOut.trim().split(/\s+/);
      if (parts.length >= 3) {
        diskTotal = parseInt(parts[1]) * 1024;
        diskUsed = parseInt(parts[2]) * 1024;
        diskPercent = Math.round((diskUsed / diskTotal) * 100);
      }
    } catch (e) {}

    // 3. Fail2ban
    let jails = [];
    let bannedTotal = 0;
    let recentBanned = [];
    
    try {
      const { stdout: jailsOut } = await execP('sudo /usr/bin/fail2ban-client status');
      const jailMatch = jailsOut.match(/Jail list:\s*(.*)/);
      if (jailMatch && jailMatch[1]) {
        jails = jailMatch[1].split(',').map(s => s.trim());
      }

      for (const jail of jails) {
        const { stdout: jailOut } = await execP(`sudo /usr/bin/fail2ban-client status ${jail}`);
        const bannedMatch = jailOut.match(/Currently banned:\s*(\d+)/);
        if (bannedMatch) bannedTotal += parseInt(bannedMatch[1], 10);
        
        const ipMatch = jailOut.match(/Banned IP list:\s*(.*)/);
        if (ipMatch && ipMatch[1]) {
          const ips = ipMatch[1].trim().split(/\s+/);
          for (const ip of ips) {
            if (ip && recentBanned.length < 10) {
              recentBanned.push({ ip, jail });
            }
          }
        }
      }
    } catch (e) {
      console.error('fail2ban status error', e.message);
    }

    // 4. Failed Services
    let failedServices = [];
    try {
      const { stdout: sysOut } = await execP('systemctl list-units --state=failed --no-legend');
      failedServices = sysOut.split('\n')
        .filter(line => line.trim())
        .map(line => line.trim().split(/\s+/)[0]);
    } catch (e) {}

    res.json({
      ok: true,
      system: {
        uptimeSeconds,
        mem: { percent: memPercent, used: usedMem, total: totalMem },
        disk: { percent: diskPercent, used: diskUsed, total: diskTotal }
      },
      fail2ban: {
        jails,
        bannedTotal,
        recentBanned
      },
      failedServices
    });

  } catch (err) {
    console.error('Status error', err);
    res.status(500).json({ ok: false, error: 'internal_error' });
  }
});

export default router;
