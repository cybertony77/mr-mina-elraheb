import { MongoClient } from 'mongodb';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import { authMiddleware } from '../../../../lib/authMiddleware';

// Load environment variables from env.config
function loadEnvConfig() {
  try {
    const envPath = path.join(process.cwd(), '..', 'env.config');
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envVars = {};
    
    envContent.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const index = trimmed.indexOf('=');
        if (index !== -1) {
          const key = trimmed.substring(0, index).trim();
          let value = trimmed.substring(index + 1).trim();
          value = value.replace(/^"|"$/g, ''); // strip quotes
          envVars[key] = value;
        }
      }
    });
    
    return envVars;
  } catch (error) {
    console.log('⚠️  Could not read env.config, using process.env as fallback');
    return {};
  }
}

const envConfig = loadEnvConfig();
const JWT_SECRET = envConfig.JWT_SECRET || process.env.JWT_SECRET || 'topphysics_secret';
const MONGO_URI = envConfig.MONGO_URI || process.env.MONGO_URI || 'mongodb://localhost:27017/topphysics';
const DB_NAME = envConfig.DB_NAME || process.env.DB_NAME || 'topphysics';

console.log('🔗 Using Mongo URI:', MONGO_URI);

async function requireAdmin(req) {
  const user = await authMiddleware(req);
  if (user.role !== 'admin' && user.role !== 'developer') {
    throw new Error('Forbidden: Admins or Developers only');
  }
  return user;
}

export default async function handler(req, res) {
  const { id } = req.query;
  if (typeof id !== 'string') {
    return res.status(400).json({ error: 'Invalid ID' });
  }
  const safeQueryId = String(id).replace(/[$]/g, '');
  let client;
  try {
    client = await MongoClient.connect(MONGO_URI);
    const db = client.db(DB_NAME);
    
    const admin = await requireAdmin(req);
    
    if (req.method === 'GET') {
      const assistant = await db.collection('assistants')
        .findOne({ id: safeQueryId }, { projection: { password: 0 } });
      if (!assistant) return res.status(404).json({ error: 'Assistant not found' });
      res.json({ 
        ...assistant,
        account_state: assistant.account_state || "Activated"
      });
    } else if (req.method === 'PUT') {
      const { id: newId, name, phone, password, role, account_state } = req.body;
      
      const update = {};
      
      if (name !== undefined && name !== null && typeof name === 'string' && name.trim() !== '') {
        update.name = name.replace(/[$]/g, '');
      }
      if (phone !== undefined && phone !== null && typeof phone === 'string' && phone.trim() !== '') {
        update.phone = phone.replace(/[$]/g, '');
      }
      if (role !== undefined && role !== null && typeof role === 'string' && role.trim() !== '') {
        update.role = role.replace(/[$]/g, '');
      }
      if (password !== undefined && password !== null && typeof password === 'string' && password.trim() !== '') {
        update.password = await bcrypt.hash(password, 10);
      }
      if (newId && typeof newId === 'string' && newId !== safeQueryId && newId.trim() !== '') {
        const safeNewId = String(newId).replace(/[$]/g, '');
        const exists = await db.collection('assistants').findOne({ id: safeNewId });
        if (exists) {
          return res.status(409).json({ error: 'Assistant ID already exists' });
        }
        update.id = safeNewId;
      }
      if (account_state !== undefined && account_state !== null && typeof account_state === 'string') {
        update.account_state = account_state;
      }
      
      if (Object.keys(update).length === 0) {
        return res.status(400).json({ error: 'No valid fields to update' });
      }
      
      const result = await db.collection('assistants').updateOne({ id: safeQueryId }, { $set: update });
      if (result.matchedCount === 0) return res.status(404).json({ error: 'Assistant not found' });
      res.json({ success: true });
    } else if (req.method === 'DELETE') {
      const result = await db.collection('assistants').deleteOne({ id: safeQueryId });
      if (result.deletedCount === 0) return res.status(404).json({ error: 'Assistant not found' });
      res.json({ success: true });
    } else {
      res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    if (error.message === 'Unauthorized') {
      res.status(401).json({ error: 'Unauthorized' });
    } else if (error.message === 'Forbidden: Admins only') {
      res.status(403).json({ error: 'Forbidden: Admins only' });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  } finally {
    if (client) await client.close();
  }
} 