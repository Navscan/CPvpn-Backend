// lib/wireguard.js — WireGuard peer management via wg(8)
// v2.0.1 — Added MTU to client config to prevent fragmentation.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileP = promisify(execFile);

const INTERFACE = process.env.WG_INTERFACE || 'wg0';
const CONFIG_PATH = process.env.WG_CONFIG_PATH || '/etc/wireguard/wg0.conf';
const ENDPOINT = process.env.WG_ENDPOINT;
const SERVER_PUBLIC_KEY = process.env.WG_SERVER_PUBLIC_KEY;
const DNS = process.env.WG_DNS || '1.1.1.1';

if (!ENDPOINT || !SERVER_PUBLIC_KEY) {
  throw new Error('WG_ENDPOINT and WG_SERVER_PUBLIC_KEY are required');
}

async function wg(args) {
  const { stdout } = await execFileP('sudo', ['/usr/bin/wg', ...args], { timeout: 5000 });
  return stdout;
}

function wgPubkeyFromPrivate(privateKey) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'sudo',
      ['/usr/bin/wg', 'pubkey'],
      { timeout: 5000 },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`wg pubkey failed: ${err.message} stderr=${stderr}`));
          return;
        }
        resolve(stdout.trim());
      }
    );
    if (child.stdin) {
      child.stdin.write(privateKey + '\n');
      child.stdin.end();
    }
  });
}

export async function generateKeypair() {
  const { stdout: priv } = await execFileP('sudo', ['/usr/bin/wg', 'genkey'], { timeout: 5000 });
  const privateKey = priv.trim();
  const publicKey = await wgPubkeyFromPrivate(privateKey);
  return { privateKey, publicKey };
}

export async function addPeer({ publicKey, allowedIp, persistentKeepalive = 25 }) {
  await wg([
    'set', INTERFACE,
    'peer', publicKey,
    'allowed-ips', `${allowedIp}/32`,
    'persistent-keepalive', String(persistentKeepalive),
  ]);
}

export async function removePeer(publicKey) {
  try {
    await wg(['set', INTERFACE, 'peer', publicKey, 'remove']);
  } catch (err) {
    if (!String(err.stderr || err.message).includes('Unable to modify interface')) {
      throw err;
    }
  }
}

export async function listPeers() {
  const out = await wg(['show', INTERFACE, 'peers']);
  return out.trim().split('\n').filter(Boolean);
}

export async function getPeerHandshake(publicKey) {
  try {
    const out = await wg(['show', INTERFACE, 'latest-handshakes']);
    const line = out.split('\n').find(l => l.startsWith(publicKey));
    if (!line) return null;
    const [, timestamp] = line.split('\t');
    const ts = parseInt(timestamp, 10);
    if (!ts) return null;
    return new Date(ts * 1000);
  } catch {
    return null;
  }
}

export async function persistPeer({ publicKey, allowedIp, persistentKeepalive = 25 }) {
  const block = [
    '',
    '[Peer]',
    `PublicKey = ${publicKey}`,
    `AllowedIPs = ${allowedIp}/32`,
    `PersistentKeepalive = ${persistentKeepalive}`,
  ].join('\n') + '\n';

  await new Promise((resolve, reject) => {
    const child = execFile('sudo', ['/usr/bin/tee', '-a', CONFIG_PATH], (err) => {
      if (err) reject(err);
      else resolve();
    });
    child.stdin.write(block);
    child.stdin.end();
  });
}

export async function unpersistPeer(publicKey) {
  const { stdout: content } = await execFileP('sudo', ['/usr/bin/cat', CONFIG_PATH]);
  const lines = content.split('\n');
  const output = [];
  let skip = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '[Peer]') {
      let isTarget = false;
      for (let j = i + 1; j < lines.length; j++) {
        const peek = lines[j].trim();
        if (peek.startsWith('[')) break;
        if (peek === `PublicKey = ${publicKey}`) {
          isTarget = true;
          break;
        }
      }
      if (isTarget) {
        skip = true;
        continue;
      }
    }

    if (skip) {
      if (line.trim().startsWith('[')) {
        skip = false;
        output.push(line);
      }
      continue;
    }
    output.push(line);
  }

  await new Promise((resolve, reject) => {
    const child = execFile('sudo', ['/usr/bin/tee', CONFIG_PATH], (err) => {
      if (err) reject(err);
      else resolve();
    });
    child.stdin.write(output.join('\n'));
    child.stdin.end();
  });
}

export function buildClientConfig({ privateKey, allowedIp, endpoint, serverPublicKey }) {
  const finalEndpoint = endpoint || ENDPOINT;
  const finalPubKey = serverPublicKey || SERVER_PUBLIC_KEY;
  
  return [
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${allowedIp}/32`,
    `DNS = ${DNS}`,
    'MTU = 1420',
    '',
    '[Peer]',
    `PublicKey = ${finalPubKey}`,
    `Endpoint = ${finalEndpoint}`,
    'AllowedIPs = 0.0.0.0/0',
    'PersistentKeepalive = 25',
    '',
  ].join('\n');
}
