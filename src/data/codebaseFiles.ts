export interface ProjectFile {
  path: string;
  name: string;
  folder: string;
  language: 'python' | 'html' | 'markdown' | 'powershell' | 'ini' | 'text' | 'javascript' | 'typescript' | 'json' | 'yaml';
  content: string;
}

export const MERN_CODEBASE_FILES: ProjectFile[] = [
  {
    path: 'docker-compose.yml',
    name: 'docker-compose.yml',
    folder: 'Root',
    language: 'yaml',
    content: `version: '3.8'

services:
  # 1. MongoDB Database
  mongodb:
    image: mongo:7.0
    container_name: pbl_mongodb
    restart: always
    environment:
      MONGO_INITDB_ROOT_USERNAME: mongoadmin
      MONGO_INITDB_ROOT_PASSWORD: secretpassword123
      MONGO_INITDB_DATABASE: secure_vault
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

  # 2. MinIO S3-Compatible Cloud Storage (Local Development)
  minio:
    image: minio/minio:RELEASE.2024-05-10T01-41-38Z
    container_name: pbl_minio
    restart: always
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadminpassword
    ports:
      - "9000:9000"   # S3 API endpoint
      - "9001:9001"   # MinIO Web Console UI
    volumes:
      - minio_data:/data

  # 3. Automated MinIO Bucket Initializer
  minio-create-bucket:
    image: minio/mc
    depends_on:
      - minio
    entrypoint: >
      /bin/sh -c "
      /usr/bin/mc alias set myminio http://minio:9000 minioadmin minioadminpassword;
      /usr/bin/mc mb myminio/secure-cloud-files;
      /usr/bin/mc anonymous set none myminio/secure-cloud-files;
      exit 0;
      "

volumes:
  mongo_data:
  minio_data:
`
  },
  {
    path: 'README.md',
    name: 'README.md',
    folder: 'Root',
    language: 'markdown',
    content: `# Secure Cloud File Storage Using Client-Side Encryption (Zero-Knowledge Architecture)
Stack: React.js (Vite) + Web Crypto API + Node.js/Express + MongoDB (Mongoose) + Amazon S3 / MinIO

## 1. Quickstart (Single Command)
docker compose up -d

## 2. Start Backend
cd backend
npm install
npm run dev

## 3. Start Frontend
cd frontend
npm install
npm run dev
`
  },
  {
    path: 'backend/package.json',
    name: 'package.json',
    folder: 'backend',
    language: 'json',
    content: `{
  "name": "secure-cloud-storage-backend",
  "version": "1.0.0",
  "description": "Zero-Knowledge Cloud File Storage Backend using Express, MongoDB, and Amazon S3 / MinIO",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "@aws-sdk/client-s3": "^3.587.0",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.4.1",
    "multer": "^1.4.5-lts.1"
  },
  "devDependencies": {
    "nodemon": "^3.1.2"
  }
}`
  },
  {
    path: 'backend/.env.example',
    name: '.env.example',
    folder: 'backend',
    language: 'ini',
    content: `PORT=5000
NODE_ENV=development
JWT_SECRET=super_secret_jwt_key_change_in_production_pbl_2026
JWT_EXPIRES_IN=7d
MONGODB_URI=mongodb://localhost:27017/secure_vault
STORAGE_PROVIDER=minio
S3_BUCKET_NAME=secure-cloud-files
S3_REGION=us-east-1
S3_ENDPOINT=http://127.0.0.1:9000
S3_FORCE_PATH_STYLE=true
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=minioadminpassword
`
  },
  {
    path: 'backend/server.js',
    name: 'server.js',
    folder: 'backend',
    language: 'javascript',
    content: `require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./src/config/db');

const app = express();
const PORT = process.env.PORT || 5000;

connectDB();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/files', require('./src/routes/files'));

app.listen(PORT, () => {
  console.log(\`Zero-Knowledge Storage Backend running on port \${PORT}\`);
});
`
  },
  {
    path: 'backend/src/config/db.js',
    name: 'db.js',
    folder: 'backend/src/config',
    language: 'javascript',
    content: `const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/secure_vault');
    console.log(\`[MongoDB Connected] \${conn.connection.host}\`);
  } catch (error) {
    console.error(\`[MongoDB Error] \${error.message}\`);
  }
};

module.exports = connectDB;
`
  },
  {
    path: 'backend/src/config/s3.js',
    name: 's3.js',
    folder: 'backend/src/config',
    language: 'javascript',
    content: `const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

const isMinio = (process.env.STORAGE_PROVIDER || 'minio').toLowerCase() === 'minio';

const s3Config = {
  region: process.env.S3_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'minioadmin',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'minioadminpassword'
  }
};

if (process.env.S3_ENDPOINT || isMinio) {
  s3Config.endpoint = process.env.S3_ENDPOINT || 'http://127.0.0.1:9000';
  s3Config.forcePathStyle = true;
}

const s3Client = new S3Client(s3Config);
const BUCKET_NAME = process.env.S3_BUCKET_NAME || 'secure-cloud-files';

const storageService = {
  async uploadCiphertext(storageKey, ciphertextBuffer, mimeType = 'application/octet-stream') {
    const command = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: storageKey,
      Body: ciphertextBuffer,
      ContentType: mimeType
    });
    await s3Client.send(command);
    return \`s3://\${BUCKET_NAME}/\${storageKey}\`;
  },

  async getCiphertext(storageKey) {
    const command = new GetObjectCommand({ Bucket: BUCKET_NAME, Key: storageKey });
    const response = await s3Client.send(command);
    const chunks = [];
    for await (const chunk of response.Body) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  },

  async deleteObject(storageKey) {
    const command = new DeleteObjectCommand({ Bucket: BUCKET_NAME, Key: storageKey });
    await s3Client.send(command);
    return true;
  }
};

module.exports = { s3Client, storageService, BUCKET_NAME };
`
  },
  {
    path: 'backend/src/models/User.js',
    name: 'User.js',
    folder: 'backend/src/models',
    language: 'javascript',
    content: `const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true },
  userSalt: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
`
  },
  {
    path: 'backend/src/models/File.js',
    name: 'File.js',
    folder: 'backend/src/models',
    language: 'javascript',
    content: `const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  originalName: { type: String, required: true },
  mimeType: { type: String, default: 'application/octet-stream' },
  originalSize: { type: Number, required: true },
  encryptedSize: { type: Number, required: true },
  storageKey: { type: String, required: true, unique: true },
  s3Bucket: { type: String, required: true },
  ivHex: { type: String, required: true },
  authTagHex: { type: String, required: true },
  saltHex: { type: String, required: true },
  encryptionAlgorithm: { type: String, default: 'AES-256-GCM (Web Crypto API)' },
  zeroKnowledge: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('File', fileSchema);
`
  },
  {
    path: 'backend/src/routes/files.js',
    name: 'files.js',
    folder: 'backend/src/routes',
    language: 'javascript',
    content: `const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const File = require('../models/File');
const auth = require('../middleware/auth');
const { storageService, BUCKET_NAME } = require('../config/s3');

router.use(auth);

// GET /api/files/list
router.get('/list', async (req, res) => {
  const files = await File.find({ owner: req.user._id }).sort({ createdAt: -1 });
  res.json({ files });
});

// POST /api/files/upload - Receives already-encrypted ciphertext
router.post('/upload', async (req, res) => {
  const { originalName, mimeType, originalSize, base64Ciphertext, ivHex, authTagHex, saltHex } = req.body;
  const ciphertextBuffer = Buffer.from(base64Ciphertext, 'base64');
  const storageKey = \`enc_\${req.user._id}_\${crypto.randomBytes(8).toString('hex')}.enc\`;

  await storageService.uploadCiphertext(storageKey, ciphertextBuffer, mimeType);

  const fileDoc = new File({
    owner: req.user._id,
    originalName,
    mimeType,
    originalSize: Number(originalSize) || ciphertextBuffer.length,
    encryptedSize: ciphertextBuffer.length,
    storageKey,
    s3Bucket: BUCKET_NAME,
    ivHex,
    authTagHex,
    saltHex,
    zeroKnowledge: true
  });

  await fileDoc.save();
  res.status(201).json({ message: 'Zero-knowledge upload successful', file: fileDoc });
});

// GET /api/files/download/:id - Retrieves ciphertext for in-browser client decryption
router.get('/download/:id', async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file || file.owner.toString() !== req.user._id.toString()) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const ciphertextBuffer = await storageService.getCiphertext(file.storageKey);
  res.json({
    fileName: file.originalName,
    mimeType: file.mimeType,
    ivHex: file.ivHex,
    authTagHex: file.authTagHex,
    saltHex: file.saltHex,
    base64Ciphertext: ciphertextBuffer.toString('base64')
  });
});

module.exports = router;
`
  },
  {
    path: 'frontend/package.json',
    name: 'package.json',
    folder: 'frontend',
    language: 'json',
    content: `{
  "name": "secure-cloud-storage-frontend",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build"
  },
  "dependencies": {
    "axios": "^1.7.2",
    "react": "^18.3.1",
    "react-dom": "^18.3.1"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.0",
    "tailwindcss": "^3.4.4",
    "typescript": "^5.2.2",
    "vite": "^5.3.1"
  }
}`
  },
  {
    path: 'frontend/src/services/crypto.ts',
    name: 'crypto.ts',
    folder: 'frontend/src/services',
    language: 'typescript',
    content: `// Client-Side Web Cryptography API
export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const rawKeyMaterial = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    rawKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptFileClientSide(dataBuffer: ArrayBuffer, passphrase: string) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const cryptoKey = await deriveKey(passphrase, salt);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    cryptoKey,
    dataBuffer
  );

  const payloadArray = new Uint8Array(encrypted);
  const tagBytes = payloadArray.slice(payloadArray.length - 16);

  return {
    base64Ciphertext: window.btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    ivHex: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
    authTagHex: Array.from(tagBytes).map(b => b.toString(16).padStart(2, '0')).join(''),
    saltHex: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''),
    encryptedSize: encrypted.byteLength
  };
}
`
  }
];

export const FLASK_CODEBASE_FILES: ProjectFile[] = [
  {
    path: 'app.py',
    name: 'app.py',
    folder: 'Root',
    language: 'python',
    content: `from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
`
  },
  {
    path: 'config.py',
    name: 'config.py',
    folder: 'Root',
    language: 'python',
    content: `import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
    DATABASE_PATH = os.environ.get('DATABASE_PATH', str(BASE_DIR / 'instance' / 'secure_vault.sqlite'))
    MASTER_ENCRYPTION_KEY = os.environ.get('MASTER_ENCRYPTION_KEY', 'college_pbl_aes256gcm_master_key_secret_2026_demo_key')
    STORAGE_BACKEND = os.environ.get('STORAGE_BACKEND', 'local').lower()
    LOCAL_STORAGE_DIR = os.environ.get('LOCAL_STORAGE_DIR', str(BASE_DIR / 'instance' / 'vault_encrypted_storage'))
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', '')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', '')
`
  },
  {
    path: 'requirements.txt',
    name: 'requirements.txt',
    folder: 'Root',
    language: 'text',
    content: `Flask==3.0.3\nWerkzeug==3.0.3\ncryptography==42.0.7\nboto3==1.34.114\npython-dotenv==1.0.1\npytest==8.2.1\n`
  },
  {
    path: 'run_windows.ps1',
    name: 'run_windows.ps1',
    folder: 'Root',
    language: 'powershell',
    content: `# Windows PowerShell Setup & Run Script
python -m venv venv
.\\venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
pytest -v
python app.py
`
  }
];
