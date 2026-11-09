require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./src/config/db');

const app = express();
const PORT = process.env.PORT || 5000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors({ origin: true, credentials: true }));
// 50MB body limit for encrypted ciphertext payloads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    project: 'Secure Cloud File Storage (Zero-Knowledge)',
    encryptionStandard: 'Client-Side AES-256-GCM (Web Crypto API)',
    storage: process.env.STORAGE_PROVIDER || 'minio'
  });
});

// API Routes
app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/files', require('./src/routes/files'));
app.use('/api/users', require('./src/routes/users'));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('[Server Error]', err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    zeroKnowledgeGuaranteed: true
  });
});

app.listen(PORT, () => {
  console.log(`========================================================`);
  console.log(`  ZERO-KNOWLEDGE CLOUD STORAGE BACKEND ACTIVE`);
  console.log(`  Running on http://localhost:${PORT}`);
  console.log(`  Storage Target: ${(process.env.STORAGE_PROVIDER || 'minio').toUpperCase()}`);
  console.log(`  Security: Plaintext is NEVER received or stored.`);
  console.log(`========================================================`);
});
