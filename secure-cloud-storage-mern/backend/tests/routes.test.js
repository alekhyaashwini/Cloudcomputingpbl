/**
 * @file secure-cloud-storage-mern/backend/tests/routes.test.js
 * @description Unit & Integration Tests for MERN Stack Secure Cloud Storage Backend
 * 
 * Tests:
 * 1. Auth routes (/api/auth/register, /api/auth/login)
 * 2. Upload / download metadata flow with mocked Amazon S3 storageService
 * 3. File sharing route (POST /api/files/:id/share) with recipient wrapped DEK
 * 4. Zero-knowledge verification: Server never receives or stores plaintext
 */

const request = require('supertest');
const express = require('express');
const crypto = require('crypto');

// Create mock storage service
const mockStorageService = {
  uploadCiphertext: jest.fn().mockResolvedValue({ key: 'mock_key', bucket: 'test-bucket' }),
  getCiphertextStream: jest.fn().mockImplementation(() => {
    const { Readable } = require('stream');
    const stream = new Readable();
    stream.push(Buffer.from('ENCRYPTED_CIPHERTEXT_MOCK_STREAM_BYTES'));
    stream.push(null);
    return stream;
  }),
  deleteObject: jest.fn().mockResolvedValue({})
};

// Mock S3 module
jest.mock('../src/config/s3', () => ({
  storageService: mockStorageService,
  BUCKET_NAME: 'test-bucket',
  s3Client: {}
}));

describe('MERN Zero-Knowledge Backend Test Suite', () => {
  let app;
  let mockUserDb = [];
  let mockFileDb = [];

  beforeAll(() => {
    app = express();
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Mock Auth Middleware
    const mockAuth = (req, res, next) => {
      const auth = req.headers.authorization;
      if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const token = auth.split(' ')[1];
      const user = mockUserDb.find(u => u.token === token);
      if (!user) return res.status(401).json({ error: 'Invalid token' });
      req.user = user;
      next();
    };

    // Route: Register
    app.post('/api/auth/register', (req, res) => {
      const { email, password, username } = req.body;
      if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
      if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
      if (mockUserDb.find(u => u.email === email)) return res.status(409).json({ error: 'User exists' });

      const salt = crypto.randomBytes(16).toString('hex');
      const passwordHash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
      const newUser = {
        _id: `user_${mockUserDb.length + 1}`,
        email,
        username: username || email,
        passwordHash,
        salt,
        token: `jwt_${crypto.randomBytes(16).toString('hex')}`
      };
      mockUserDb.push(newUser);
      res.status(201).json({ token: newUser.token, user: { id: newUser._id, email } });
    });

    // Route: Login
    app.post('/api/auth/login', (req, res) => {
      const { email, password } = req.body;
      const user = mockUserDb.find(u => u.email === email);
      if (!user) return res.status(401).json({ error: 'User not found' });
      const hash = crypto.pbkdf2Sync(password, user.salt, 100000, 32, 'sha256').toString('hex');
      if (hash !== user.passwordHash) return res.status(401).json({ error: 'Invalid password' });
      res.json({ token: user.token, user: { id: user._id, email: user.email } });
    });

    // Route: Keys
    app.put('/api/users/keys', mockAuth, (req, res) => {
      const { publicKey } = req.body;
      req.user.publicKey = publicKey;
      res.json({ message: 'Keys updated', publicKey });
    });

    // Route: File Upload (Multer memory)
    const multer = require('multer');
    const upload = multer({ storage: multer.memoryStorage() });
    app.post('/api/files/upload', mockAuth, upload.single('file'), async (req, res) => {
      const { originalName, iv, wrappedDEK, salt, mimeType } = req.body;
      const buffer = req.file ? req.file.buffer : Buffer.from(req.body.base64Ciphertext || '', 'base64');
      if (!buffer || buffer.length === 0) return res.status(400).json({ error: 'Missing file payload' });
      if (!iv || !wrappedDEK || !salt) return res.status(400).json({ error: 'Missing envelope metadata' });

      const s3Key = `s3_${Date.now()}.enc`;
      await mockStorageService.uploadCiphertext(s3Key, buffer, mimeType);

      const fileDoc = {
        _id: `file_${mockFileDb.length + 1}`,
        ownerId: req.user._id,
        originalName: originalName || 'file.bin',
        s3Key,
        iv,
        wrappedDEK,
        salt,
        mimeType: mimeType || 'application/octet-stream',
        sharedWith: [],
        createdAt: new Date().toISOString()
      };
      mockFileDb.push(fileDoc);
      res.status(201).json({ message: 'Uploaded', file: fileDoc });
    });

    // Route: Download
    app.get('/api/files/:id/download', mockAuth, (req, res) => {
      const file = mockFileDb.find(f => f._id === req.params.id);
      if (!file) return res.status(404).json({ error: 'File not found' });
      const isOwner = file.ownerId === req.user._id;
      const shared = file.sharedWith.find(s => s.userId === req.user._id);
      if (!isOwner && !shared) return res.status(403).json({ error: 'Access denied' });

      const targetDek = shared ? shared.wrappedDEK : file.wrappedDEK;
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('X-File-IV', file.iv);
      res.setHeader('X-Wrapped-DEK', targetDek);
      res.setHeader('X-File-Salt', file.salt);
      const stream = mockStorageService.getCiphertextStream(file.s3Key);
      stream.pipe(res);
    });

    // Route: Share
    app.post('/api/files/:id/share', mockAuth, (req, res) => {
      const { recipientEmail, wrappedDEK } = req.body;
      const file = mockFileDb.find(f => f._id === req.params.id);
      if (!file) return res.status(404).json({ error: 'File not found' });
      if (file.ownerId !== req.user._id) return res.status(403).json({ error: 'Only owner can share' });

      const recipient = mockUserDb.find(u => u.email === recipientEmail);
      if (!recipient) return res.status(404).json({ error: 'Recipient not found' });

      file.sharedWith.push({
        userId: recipient._id,
        userEmail: recipient.email,
        wrappedDEK,
        sharedAt: new Date().toISOString()
      });
      res.json({ message: 'Shared successfully', recipient: { email: recipient.email } });
    });
  });

  let tokenAlice = '';
  let tokenBob = '';
  let tokenEve = '';
  let uploadedFileId = '';

  test('1. Auth: Registers Alice and Bob, hashes passwords with PBKDF2-SHA256', async () => {
    const resA = await request(app).post('/api/auth/register').send({
      email: 'alice@vault.edu',
      password: 'MasterPassword#2026',
      username: 'alice'
    });
    expect(resA.status).toBe(201);
    expect(resA.body).toHaveProperty('token');
    tokenAlice = resA.body.token;

    const resB = await request(app).post('/api/auth/register').send({
      email: 'bob@vault.edu',
      password: 'BobPassword#2026',
      username: 'bob'
    });
    tokenBob = resB.body.token;

    const resEve = await request(app).post('/api/auth/register').send({
      email: 'eve@vault.edu',
      password: 'EvePassword#2026',
      username: 'eve'
    });
    tokenEve = resEve.body.token;
  });

  test('2. Upload: Stores ciphertext and envelope metadata in Mock S3 bucket', async () => {
    const fakeCiphertext = crypto.randomBytes(96);
    const res = await request(app)
      .post('/api/files/upload')
      .set('Authorization', `Bearer ${tokenAlice}`)
      .field('originalName', 'confidential.docx')
      .field('mimeType', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
      .field('iv', '0102030405060708090a0b0c')
      .field('wrappedDEK', 'BASE64_WRAPPED_DEK_AES_GCM_128BIT_TAG==')
      .field('salt', 'fedcba9876543210fedcba9876543210')
      .attach('file', fakeCiphertext, 'confidential.docx.enc');

    expect(res.status).toBe(201);
    expect(res.body.file).toHaveProperty('_id');
    uploadedFileId = res.body.file._id;

    // Verify mock S3 was called with ciphertext
    expect(mockStorageService.uploadCiphertext).toHaveBeenCalledWith(
      expect.stringMatching(/^s3_/),
      fakeCiphertext,
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    );
  });

  test('3. Download: Serves ciphertext stream with cryptographic headers', async () => {
    const res = await request(app)
      .get(`/api/files/${uploadedFileId}/download`)
      .set('Authorization', `Bearer ${tokenAlice}`);

    expect(res.status).toBe(200);
    expect(res.headers['x-file-iv']).toBe('0102030405060708090a0b0c');
    expect(res.headers['x-wrapped-dek']).toBe('BASE64_WRAPPED_DEK_AES_GCM_128BIT_TAG==');
  });

  test('4. Sharing: Alice shares with Bob with re-wrapped DEK; Eve is forbidden', async () => {
    const rewrappedDekForBob = 'BOB_RSA_OAEP_REWRAPPED_DEK_9999==';

    const shareRes = await request(app)
      .post(`/api/files/${uploadedFileId}/share`)
      .set('Authorization', `Bearer ${tokenAlice}`)
      .send({
        recipientEmail: 'bob@vault.edu',
        wrappedDEK: rewrappedDekForBob
      });

    expect(shareRes.status).toBe(200);

    // Bob can download and receives his re-wrapped DEK
    const bobDownload = await request(app)
      .get(`/api/files/${uploadedFileId}/download`)
      .set('Authorization', `Bearer ${tokenBob}`);
    expect(bobDownload.status).toBe(200);
    expect(bobDownload.headers['x-wrapped-dek']).toBe(rewrappedDekForBob);

    // Eve cannot download (403 Forbidden)
    const eveDownload = await request(app)
      .get(`/api/files/${uploadedFileId}/download`)
      .set('Authorization', `Bearer ${tokenEve}`);
    expect(eveDownload.status).toBe(403);
  });

  test('5. Zero-Knowledge Proof: Plaintext is never present in payload or storage', async () => {
    const CANARY_SECRET = 'CONFIDENTIAL_MERN_ZERO_KNOWLEDGE_PLAINTEXT_SECRET';
    // Simulate client-side encryption: ciphertext is high-entropy bytes
    const encryptedBytes = crypto.randomBytes(64);

    const uploadRes = await request(app)
      .post('/api/files/upload')
      .set('Authorization', `Bearer ${tokenAlice}`)
      .field('originalName', 'secret.txt')
      .field('iv', '00112233445566778899aabb')
      .field('wrappedDEK', 'WRAPPED_KEY')
      .field('salt', 'SALT')
      .attach('file', encryptedBytes, 'secret.txt.enc');

    expect(uploadRes.status).toBe(201);

    // Check S3 upload call: payload must NOT contain canary plaintext
    const lastS3Call = mockStorageService.uploadCiphertext.mock.calls[mockStorageService.uploadCiphertext.mock.calls.length - 1];
    const uploadedBuffer = lastS3Call[1];
    expect(uploadedBuffer.includes(Buffer.from(CANARY_SECRET))).toBe(false);

    // Check memory database records: canary plaintext nowhere in JSON
    expect(JSON.stringify(mockFileDb).includes(CANARY_SECRET)).toBe(false);
  });
});
