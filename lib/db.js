import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB || 'cpvpn';

if (!uri) {
  throw new Error('MONGODB_URI is required');
}

const client = new MongoClient(uri, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 30000,
});

let db = null;

export async function connect() {
  if (db) return db;

  await client.connect();
  db = client.db(dbName);

  const peers = db.collection('peers');
  await peers.createIndex({ publicKey: 1 }, { unique: true });
  
  // Drop the old strict IP index
  try {
    await peers.dropIndex('ip_1');
  } catch (e) {
    // Ignore if index doesn't exist yet
  }
  
  // Create a partial unique index that only applies to active peers
  await peers.createIndex(
    { ip: 1 }, 
    { unique: true, partialFilterExpression: { revokedAt: null } }
  );
  
  await peers.createIndex({ email: 1 });
  await peers.createIndex({ revokedAt: 1 });
  await peers.createIndex({ createdAt: 1 });

  const users = db.collection('cpvpn_users');
  await users.createIndex({ email: 1 }, { unique: true });
  await users.createIndex({ tier: 1 });
  await users.createIndex({ is_active: 1 });

  return db;
}

export function getDb() {
  if (!db) throw new Error('Database not connected. Call connect() first.');
  return db;
}

export function peers() {
  return getDb().collection('peers');
}

export function users() {
  return getDb().collection('cpvpn_users');
}

export async function close() {
  if (client) {
    await client.close();
  }
  db = null;
}
