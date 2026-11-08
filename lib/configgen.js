// lib/configgen.js — IP allocation and client-config assembly
// v2.0.0 — Multi-server support based on user tier.

import { peers } from './db.js';
import { generateKeypair, buildClientConfig } from './wireguard.js';

const POOL_START = process.env.IP_POOL_START || '10.0.0.4';
const POOL_END = process.env.IP_POOL_END || '10.0.0.254';

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function intToIp(n) {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join('.');
}

const START_INT = ipToInt(POOL_START);
const END_INT = ipToInt(POOL_END);

export async function allocateIp() {
  const active = await peers()
    .find({ revokedAt: null }, { projection: { ip: 1 } })
    .toArray();

  const taken = new Set(active.map(p => p.ip));

  for (let n = START_INT; n <= END_INT; n++) {
    const candidate = intToIp(n);
    if (!taken.has(candidate)) {
      return candidate;
    }
  }

  throw new Error('IP pool exhausted');
}

export async function buildFreshPeerConfig(tier = 'free') {
  const { privateKey, publicKey } = await generateKeypair();
  const allowedIp = await allocateIp();

  // Determine server based on tier
  let endpoint = process.env.WG_ENDPOINT;
  let serverPublicKey = process.env.WG_SERVER_PUBLIC_KEY;
  let location = 'South Africa';
  let flag = '🇿🇦';

  // If user is Pro or Enterprise, check if a premium server is configured
  if (tier === 'pro' || tier === 'enterprise') {
    if (process.env.WG_ENDPOINT_PREMIUM && process.env.WG_SERVER_PUBLIC_KEY_PREMIUM) {
      endpoint = process.env.WG_ENDPOINT_PREMIUM;
      serverPublicKey = process.env.WG_SERVER_PUBLIC_KEY_PREMIUM;
      location = 'Europe'; // Customize this when you deploy
      flag = '🇪🇺';       // Customize this when you deploy
    }
  }

  const clientConfig = buildClientConfig({ privateKey, allowedIp, endpoint, serverPublicKey });

  return { 
    privateKey, 
    publicKey, 
    allowedIp, 
    clientConfig,
    metadata: { endpoint, location, flag } 
  };
}

export function poolSize() {
  return END_INT - START_INT + 1;
}
