import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadBucketCommand,
  CreateBucketCommand
} from '@aws-sdk/client-s3';
import { MongoClient, Db } from 'mongodb';

export interface User {
  id: string;
  username: string;
  email: string;
  passwordHash: string;
  salt: string;
  publicKey?: string;
  encryptedPrivateKey?: string;
  privateKeyIv?: string;
  privateKeySalt?: string;
  createdAt: string;
}

export interface SharedWithEntry {
  userId: string;
  userEmail: string;
  wrappedDEK: string;
  sharedAt: string;
}

export interface StoredFileMetadata {
  id: string;
  ownerId: string;
  originalName: string;
  mimeType: string;
  originalSize: number;
  encryptedSize: number;
  storageBackend: 'local' | 's3';
  storageKey: string;
  ivHex: string;         // 12-byte (96-bit) IV / Nonce in hex
  authTagHex: string;    // 16-byte (128-bit) GCM authentication tag in hex
  saltHex: string;       // Key derivation salt in hex
  keyId: string;         // Reference identifier for key rotation
  wrappedDEK?: string;   // Owner's wrapped DEK
  iv?: string;           // Base64 or string representation of IV
  salt?: string;         // Base64 or string representation of Salt
  dekIv?: string;        // Base64 or string representation of DEK IV
  size?: number;         // File size in bytes
  sharedWith?: SharedWithEntry[]; // List of recipients with re-wrapped DEKs
  createdAt: string;
  isTampered?: boolean;  // Test flag to indicate simulated corruption
}

export interface StorageConfig {
  backend: 'local' | 's3';
  s3Bucket: string;
  s3Region: string;
  s3Endpoint?: string;
  forcePathStyle?: boolean;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
}

// Master encryption key (in production, loaded from secure env var MASTER_ENCRYPTION_KEY)
const MASTER_KEY_ENV = process.env.MASTER_ENCRYPTION_KEY || 'college_pbl_aes256gcm_master_key_secret_2026_demo_key';
const DATA_DIR = path.resolve(process.cwd(), 'vault_data');
const LOCAL_STORAGE_DIR = path.resolve(DATA_DIR, 'encrypted_objects');
const DB_FILE = path.resolve(DATA_DIR, 'database.json');

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(LOCAL_STORAGE_DIR)) {
  fs.mkdirSync(LOCAL_STORAGE_DIR, { recursive: true });
}

// ==============================================================================
// S3 & MinIO CLIENT CONFIGURATION
// ==============================================================================

/**
 * Derives the active S3 / MinIO configuration from environment variables or database overrides.
 * Seamlessly supports:
 * 1. Local MinIO: S3_ENDPOINT=http://localhost:9000, S3_FORCE_PATH_STYLE=true, S3_ACCESS_KEY=minioadmin
 * 2. AWS S3 (Prod): S3_ENDPOINT="", S3_FORCE_PATH_STYLE=false, S3_REGION=us-east-1, AWS_ACCESS_KEY_ID=AKIA...
 */
export function getS3Config(): {
  endpoint?: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle: boolean;
  provider: 'minio' | 'aws' | 'custom';
} {
  const envEndpoint = (process.env.S3_ENDPOINT || process.env.AWS_ENDPOINT_URL || '').trim();
  const region = (process.env.S3_REGION || process.env.AWS_REGION || 'us-east-1').trim();
  const bucket = (process.env.S3_BUCKET_NAME || process.env.AWS_S3_BUCKET || 'secure-vault-bucket').trim();
  const accessKeyId = (process.env.S3_ACCESS_KEY || process.env.AWS_ACCESS_KEY_ID || 'minioadmin').trim();
  const secretAccessKey = (process.env.S3_SECRET_KEY || process.env.AWS_SECRET_ACCESS_KEY || 'minioadmin').trim();

  // Determine provider type
  const isMinIO = Boolean(envEndpoint && (envEndpoint.includes('localhost') || envEndpoint.includes('127.0.0.1') || envEndpoint.includes(':9000') || envEndpoint.includes('minio')));
  const provider = isMinIO ? 'minio' : (envEndpoint ? 'custom' : 'aws');

  // MinIO and S3-compatible alternatives require path-style routing: http://localhost:9000/bucket-name/key
  // AWS S3 standard uses virtual-hosted routing: https://bucket-name.s3.amazonaws.com/key
  const forcePathStyle = process.env.S3_FORCE_PATH_STYLE !== undefined
    ? process.env.S3_FORCE_PATH_STYLE === 'true'
    : Boolean(envEndpoint);

  return {
    endpoint: envEndpoint || undefined,
    region,
    bucket,
    accessKeyId,
    secretAccessKey,
    forcePathStyle,
    provider
  };
}

let cachedS3Client: S3Client | null = null;

/**
 * Returns an instantiated AWS SDK S3Client configured for MinIO (local) or AWS S3 (production).
 */
export function getS3Client(): S3Client {
  if (!cachedS3Client) {
    const cfg = getS3Config();
    cachedS3Client = new S3Client({
      region: cfg.region,
      endpoint: cfg.endpoint,
      forcePathStyle: cfg.forcePathStyle,
      credentials: {
        accessKeyId: cfg.accessKeyId,
        secretAccessKey: cfg.secretAccessKey
      }
    });
  }
  return cachedS3Client;
}

/**
 * Resets cached S3 client instance (useful when environment or runtime config changes)
 */
export function resetS3Client(): void {
  cachedS3Client = null;
}

/**
 * Ensures the target bucket exists in MinIO or AWS S3. If missing, attempts to create it.
 */
export async function ensureS3BucketExists(): Promise<boolean> {
  const client = getS3Client();
  const cfg = getS3Config();
  try {
    await client.send(new HeadBucketCommand({ Bucket: cfg.bucket }));
    return true;
  } catch (err: any) {
    // If bucket does not exist (404 / NotFound / NoSuchBucket), create it
    if (err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404 || err.name === 'NoSuchBucket') {
      try {
        console.log(`[Storage] Bucket "${cfg.bucket}" does not exist. Creating bucket on ${cfg.provider.toUpperCase()}...`);
        await client.send(new CreateBucketCommand({
          Bucket: cfg.bucket,
          // MinIO or us-east-1 does not require LocationConstraint
          CreateBucketConfiguration: cfg.region !== 'us-east-1' ? { LocationConstraint: cfg.region as any } : undefined
        }));
        console.log(`[Storage] Bucket "${cfg.bucket}" created successfully.`);
        return true;
      } catch (createErr) {
        console.warn(`[Storage] Could not auto-create bucket "${cfg.bucket}":`, createErr);
        return false;
      }
    }
    return false;
  }
}

/**
 * Health check for MinIO / AWS S3 connection.
 */
export async function testS3Connection(): Promise<{
  connected: boolean;
  provider: 'minio' | 'aws' | 'custom';
  endpoint?: string;
  bucket: string;
  forcePathStyle: boolean;
  message: string;
}> {
  const cfg = getS3Config();
  try {
    const client = getS3Client();
    await client.send(new HeadBucketCommand({ Bucket: cfg.bucket }));
    return {
      connected: true,
      provider: cfg.provider,
      endpoint: cfg.endpoint,
      bucket: cfg.bucket,
      forcePathStyle: cfg.forcePathStyle,
      message: `Successfully connected to ${cfg.provider.toUpperCase()} bucket [${cfg.bucket}]`
    };
  } catch (err: any) {
    return {
      connected: false,
      provider: cfg.provider,
      endpoint: cfg.endpoint,
      bucket: cfg.bucket,
      forcePathStyle: cfg.forcePathStyle,
      message: `Failed to connect to ${cfg.provider.toUpperCase()} (${err.message || err.name})`
    };
  }
}

// ==============================================================================
// MONGODB CONNECTION POOL (OPTIONAL HYBRID PERSISTENCE)
// ==============================================================================

let mongoClient: MongoClient | null = null;
let mongoDb: Db | null = null;
const MONGODB_URI = process.env.MONGODB_URI || '';

export async function initMongoDB(): Promise<Db | null> {
  if (mongoDb) return mongoDb;
  if (!MONGODB_URI) return null;
  try {
    mongoClient = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 2000
    });
    await mongoClient.connect();
    mongoDb = mongoClient.db();
    console.log('[MongoDB] Connected successfully to metadata store at', MONGODB_URI.replace(/:[^:@]+@/, ':****@'));
    return mongoDb;
  } catch (err: any) {
    console.warn('[MongoDB] Optional MongoDB connection unavailable (falling back to JSON store):', err.message);
    return null;
  }
}

interface DBState {
  users: User[];
  files: StoredFileMetadata[];
  config: StorageConfig;
}

function loadDB(): DBState {
  if (fs.existsSync(DB_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
      const s3Defaults = getS3Config();
      return {
        users: data.users || [],
        files: data.files || [],
        config: data.config || {
          backend: process.env.STORAGE_BACKEND === 's3' ? 's3' : 'local',
          s3Bucket: s3Defaults.bucket,
          s3Region: s3Defaults.region,
          s3Endpoint: s3Defaults.endpoint,
          forcePathStyle: s3Defaults.forcePathStyle
        }
      };
    } catch {
      // fallback
    }
  }

  // Initial seed with demo user and sample encrypted file for immediate testing
  const demoSalt = crypto.randomBytes(16).toString('hex');
  const demoPasswordHash = crypto.pbkdf2Sync('Student@123', demoSalt, 100000, 32, 'sha256').toString('hex');
  const demoUser: User = {
    id: 'user_demo_101',
    username: 'cs_student',
    email: 'student@college.edu',
    passwordHash: demoPasswordHash,
    salt: demoSalt,
    createdAt: new Date().toISOString()
  };

  // Pre-encrypt sample document
  const samplePlaintext = Buffer.from(
    "PROJECT-BASED LEARNING (PBL) VERIFICATION DOCUMENT\n" +
    "Topic: Secure Cloud File Storage Using Authenticated Encryption (AES-256-GCM)\n" +
    "Student: B.Tech Computer Science & Engineering\n" +
    "Status: Plaintext decrypted successfully from authenticated cloud vault.\n" +
    "Integrity: GHASH 128-bit MAC tag verified against ciphertext."
  );
  const sampleSalt = crypto.randomBytes(16);
  const combinedSecret = `${MASTER_KEY_ENV}::${demoUser.id}`;
  const sampleKey = crypto.pbkdf2Sync(combinedSecret, sampleSalt, 100000, 32, 'sha256');
  
  const sampleIv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sampleKey, sampleIv);
  const sampleCiphertext = Buffer.concat([cipher.update(samplePlaintext), cipher.final()]);
  const sampleAuthTag = cipher.getAuthTag();

  const sampleFileId = 'file_seed_001';
  const sampleStorageKey = `enc_${sampleFileId}.enc`;
  const sampleFilePath = path.resolve(LOCAL_STORAGE_DIR, sampleStorageKey);
  fs.writeFileSync(sampleFilePath, sampleCiphertext);
  fs.writeFileSync(path.resolve(LOCAL_STORAGE_DIR, `${sampleStorageKey}.backup`), sampleCiphertext);

  const s3Defaults = getS3Config();
  const sampleFile: StoredFileMetadata = {
    id: sampleFileId,
    ownerId: demoUser.id,
    originalName: 'PBL_Project_Abstract_and_Objectives.txt',
    mimeType: 'text/plain',
    originalSize: samplePlaintext.length,
    encryptedSize: sampleCiphertext.length,
    storageBackend: 'local',
    storageKey: sampleStorageKey,
    ivHex: sampleIv.toString('hex'),
    authTagHex: sampleAuthTag.toString('hex'),
    saltHex: sampleSalt.toString('hex'),
    keyId: 'kdf-v1-aes256gcm',
    createdAt: new Date().toISOString(),
    isTampered: false
  };

  const initial: DBState = {
    users: [demoUser],
    files: [sampleFile],
    config: {
      backend: process.env.STORAGE_BACKEND === 's3' ? 's3' : 'local',
      s3Bucket: s3Defaults.bucket,
      s3Region: s3Defaults.region,
      s3Endpoint: s3Defaults.endpoint,
      forcePathStyle: s3Defaults.forcePathStyle
    }
  };
  saveDB(initial);
  return initial;
}

function saveDB(data: DBState) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

/**
 * Derives a dedicated 256-bit AES key per user and file using PBKDF2 with SHA-256
 */
export function deriveFileKey(ownerId: string, salt: Buffer): Buffer {
  const combinedSecret = `${MASTER_KEY_ENV}::${ownerId}`;
  return crypto.pbkdf2Sync(combinedSecret, salt, 100000, 32, 'sha256');
}

/**
 * AES-256-GCM Authenticated Encryption
 */
export function encryptBuffer(plaintext: Buffer, key: Buffer): {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
} {
  // 96-bit (12 bytes) recommended random nonce for GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);
  
  const authTag = cipher.getAuthTag(); // 16 bytes authentication tag
  return { ciphertext, iv, authTag };
}

/**
 * AES-256-GCM Authenticated Decryption with Tag Verification
 */
export function decryptBuffer(
  ciphertext: Buffer,
  key: Buffer,
  iv: Buffer,
  authTag: Buffer
): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  // If ciphertext or tag was altered, decipher.final() will throw an authentication error!
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
  
  return decrypted;
}

export const db = {
  getUsers(): User[] {
    return loadDB().users;
  },
  findUserById(id: string): User | undefined {
    return loadDB().users.find(u => u.id === id);
  },
  findUserByUsernameOrEmail(identifier: string): User | undefined {
    const norm = identifier.toLowerCase().trim();
    return loadDB().users.find(u => u.username.toLowerCase() === norm || u.email.toLowerCase() === norm);
  },
  addUser(user: User) {
    const data = loadDB();
    data.users.push(user);
    saveDB(data);
  },
  updateUser(user: User) {
    const data = loadDB();
    data.users = data.users.map(u => u.id === user.id ? user : u);
    saveDB(data);
  },
  getFiles(ownerId: string): StoredFileMetadata[] {
    return loadDB().files.filter(f => f.ownerId === ownerId);
  },
  getSharedFiles(userId: string): StoredFileMetadata[] {
    return loadDB().files.filter(f => f.sharedWith && f.sharedWith.some(s => s.userId === userId));
  },
  findFileById(id: string): StoredFileMetadata | undefined {
    return loadDB().files.find(f => f.id === id);
  },
  addFile(file: StoredFileMetadata) {
    const data = loadDB();
    data.files.push(file);
    saveDB(data);
  },
  updateFile(file: StoredFileMetadata) {
    const data = loadDB();
    data.files = data.files.map(f => f.id === file.id ? file : f);
    saveDB(data);
  },
  deleteFile(id: string) {
    const data = loadDB();
    data.files = data.files.filter(f => f.id !== id);
    saveDB(data);
  },
  updateFileDek(fileId: string, ownerId: string, wrappedDEK: string, dekIv?: string, salt?: string): boolean {
    const data = loadDB();
    const file = data.files.find(f => f.id === fileId && f.ownerId === ownerId);
    if (!file) return false;
    file.wrappedDEK = wrappedDEK;
    if (dekIv) file.dekIv = dekIv;
    if (salt) {
      file.salt = salt;
      file.saltHex = salt;
    }
    saveDB(data);
    return true;
  },
  batchUpdateFileDeks(ownerId: string, updates: Array<{ fileId: string; wrappedDEK: string; dekIv?: string; salt?: string }>): number {
    const data = loadDB();
    let count = 0;
    for (const item of updates) {
      const file = data.files.find(f => f.id === item.fileId && f.ownerId === ownerId);
      if (file) {
        file.wrappedDEK = item.wrappedDEK;
        if (item.dekIv) file.dekIv = item.dekIv;
        if (item.salt) {
          file.salt = item.salt;
          file.saltHex = item.salt;
        }
        count++;
      }
    }
    if (count > 0) {
      saveDB(data);
    }
    return count;
  },
  getConfig(): StorageConfig {
    return loadDB().config;
  },
  updateConfig(config: StorageConfig) {
    const data = loadDB();
    data.config = config;
    saveDB(data);
    resetS3Client();
  }
};

/**
 * Storage adapter supporting dual operation:
 * 1. Synchronous local cache / fallback (for seamless testing & instant disk writes).
 * 2. Asynchronous S3 / MinIO object storage (via PutObject, GetObject, DeleteObject).
 */
export const storage = {
  /**
   * Saves an encrypted buffer locally, and asynchronously propagates to MinIO / AWS S3
   * when the S3 backend is enabled.
   */
  saveEncryptedObject(key: string, data: Buffer): void {
    const filePath = path.resolve(LOCAL_STORAGE_DIR, key);
    fs.writeFileSync(filePath, data);
    // Untampered backup for demo restoration
    const backupPath = path.resolve(LOCAL_STORAGE_DIR, `${key}.backup`);
    fs.writeFileSync(backupPath, data);

    // If S3 or MinIO backend is configured, upload in background
    const cfg = db.getConfig();
    if (cfg.backend === 's3' || process.env.STORAGE_BACKEND === 's3') {
      const s3Cfg = getS3Config();
      const client = getS3Client();
      client.send(new PutObjectCommand({
        Bucket: s3Cfg.bucket,
        Key: key,
        Body: data,
        ContentType: 'application/octet-stream'
      })).catch(err => {
        console.warn(`[MinIO/S3] Background PutObject failed for key "${key}":`, err.message);
      });
    }
  },

  /**
   * Async variant that awaits S3 / MinIO upload completion
   */
  async saveEncryptedObjectAsync(key: string, data: Buffer): Promise<void> {
    const filePath = path.resolve(LOCAL_STORAGE_DIR, key);
    fs.writeFileSync(filePath, data);
    const backupPath = path.resolve(LOCAL_STORAGE_DIR, `${key}.backup`);
    fs.writeFileSync(backupPath, data);

    const cfg = db.getConfig();
    if (cfg.backend === 's3' || process.env.STORAGE_BACKEND === 's3') {
      const s3Cfg = getS3Config();
      const client = getS3Client();
      await client.send(new PutObjectCommand({
        Bucket: s3Cfg.bucket,
        Key: key,
        Body: data,
        ContentType: 'application/octet-stream'
      }));
    }
  },

  /**
   * Synchronously reads an encrypted object from local filesystem
   */
  getEncryptedObject(key: string): Buffer {
    const filePath = path.resolve(LOCAL_STORAGE_DIR, key);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Encrypted cloud object [${key}] not found in storage backend`);
    }
    return fs.readFileSync(filePath);
  },

  /**
   * Asynchronously retrieves an encrypted object from MinIO / AWS S3 (falls back to local vault)
   */
  async getEncryptedObjectAsync(key: string): Promise<Buffer> {
    const cfg = db.getConfig();
    if (cfg.backend === 's3' || process.env.STORAGE_BACKEND === 's3') {
      try {
        const s3Cfg = getS3Config();
        const client = getS3Client();
        const response = await client.send(new GetObjectCommand({
          Bucket: s3Cfg.bucket,
          Key: key
        }));

        if (response.Body) {
          const stream = response.Body as any;
          const chunks: Buffer[] = [];
          for await (const chunk of stream) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
          }
          return Buffer.concat(chunks);
        }
      } catch (err: any) {
        console.warn(`[MinIO/S3] GetObject for "${key}" failed, checking local cache:`, err.message);
      }
    }
    return this.getEncryptedObject(key);
  },

  deleteEncryptedObject(key: string): void {
    const filePath = path.resolve(LOCAL_STORAGE_DIR, key);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    const backupPath = path.resolve(LOCAL_STORAGE_DIR, `${key}.backup`);
    if (fs.existsSync(backupPath)) {
      fs.unlinkSync(backupPath);
    }

    const cfg = db.getConfig();
    if (cfg.backend === 's3' || process.env.STORAGE_BACKEND === 's3') {
      const s3Cfg = getS3Config();
      const client = getS3Client();
      client.send(new DeleteObjectCommand({
        Bucket: s3Cfg.bucket,
        Key: key
      })).catch(err => {
        console.warn(`[MinIO/S3] DeleteObject for "${key}" failed:`, err.message);
      });
    }
  },

  async deleteEncryptedObjectAsync(key: string): Promise<void> {
    this.deleteEncryptedObject(key);
    const cfg = db.getConfig();
    if (cfg.backend === 's3' || process.env.STORAGE_BACKEND === 's3') {
      const s3Cfg = getS3Config();
      const client = getS3Client();
      await client.send(new DeleteObjectCommand({
        Bucket: s3Cfg.bucket,
        Key: key
      }));
    }
  },

  tamperEncryptedObject(key: string): void {
    const filePath = path.resolve(LOCAL_STORAGE_DIR, key);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Encrypted object not found for tampering test`);
    }
    const data = fs.readFileSync(filePath);
    if (data.length > 0) {
      // Flip the last bit of the first byte of ciphertext to simulate bit-flip attack
      const corrupted = Buffer.from(data);
      corrupted[0] ^= 0xFF;
      fs.writeFileSync(filePath, corrupted);
    }
  },

  restoreEncryptedObject(key: string): void {
    const backupPath = path.resolve(LOCAL_STORAGE_DIR, `${key}.backup`);
    const filePath = path.resolve(LOCAL_STORAGE_DIR, key);
    if (fs.existsSync(backupPath)) {
      fs.copyFileSync(backupPath, filePath);
    }
  }
};
