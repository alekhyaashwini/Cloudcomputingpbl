/**
 * @file tests/backend/api.test.js
 * @description Backend Integration Tests using Jest and Supertest.
 * 
 * Coverage:
 * 1. Authentication routes: /api/auth/register and /api/auth/login.
 * 2. Upload / Download metadata flow with Mock S3 / Storage Service.
 * 3. File sharing route: POST /api/files/:id/share with recipient wrapped DEK.
 * 4. Zero-Knowledge Proof Test: Explicitly asserts the server storage and database
 *    NEVER receive, inspect, or store plaintext file bytes.
 */

import request from 'supertest';
import { jest } from '@jest/globals';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import '../setup.js';
import { app, db, storage } from '../server.bundle.js';
import { encryptWithEnvelope } from '../../src/services/encryption.js';

describe('Zero-Knowledge Backend API (Supertest + Express)', () => {
  let userA = {
    username: `alice_${Date.now()}`,
    email: `alice_${Date.now()}@example.com`,
    password: 'AliceMasterPassword#2026!'
  };

  let userB = {
    username: `bob_${Date.now()}`,
    email: `bob_${Date.now()}@example.com`,
    password: 'BobMasterPassword#2026!'
  };

  let userC = {
    username: `eve_${Date.now()}`,
    email: `eve_${Date.now()}@example.com`,
    password: 'EveAttackerPassword#2026!'
  };

  let tokenA = '';
  let tokenB = '';
  let tokenC = '';
  let uploadedFileId = '';

  // =========================================================================
  // 1. AUTHENTICATION ROUTES
  // =========================================================================
  describe('1. Authentication Routes (/api/auth)', () => {
    test('POST /api/auth/register registers a new user with salted PBKDF2 password hash', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: userA.username,
          email: userA.email,
          password: userA.password
        });

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('id');
      expect(res.body.user.email).toBe(userA.email);

      // Verify server never stored plaintext password
      const storedUser = db.findUserByUsernameOrEmail(userA.email);
      expect(storedUser).toBeDefined();
      expect(storedUser.passwordHash).toBeDefined();
      expect(storedUser.passwordHash).not.toBe(userA.password);
      expect(storedUser.salt).toBeDefined();

      tokenA = res.body.token;
    });

    test('POST /api/auth/register rejects duplicate registration (409 Conflict)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: userA.username,
          email: userA.email,
          password: userA.password
        });

      expect(res.status).toBe(409);
      expect(res.body.error).toMatch(/already exists/i);
    });

    test('POST /api/auth/register rejects short passwords under 6 characters (400 Bad Request)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          username: 'shortuser',
          email: 'short@example.com',
          password: '123'
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/at least 6 characters/i);
    });

    test('POST /api/auth/login authenticates registered user and issues session token', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: userA.email,
          password: userA.password
        });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user.email).toBe(userA.email);
      tokenA = res.body.token;
    });

    test('POST /api/auth/login rejects incorrect password (401 Unauthorized)', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: userA.email,
          password: 'CompletelyWrongPassword#123'
        });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/invalid credentials|incorrect/i);
    });

    test('Register secondary users Bob and Eve for sharing & authorization tests', async () => {
      const resBob = await request(app)
        .post('/api/auth/register')
        .send(userB);
      expect(resBob.status).toBe(201);
      tokenB = resBob.body.token;

      // Publish an RSA public key for Bob
      await request(app)
        .put('/api/users/keys')
        .set('Authorization', `Bearer ${tokenB}`)
        .send({
          publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA_MOCK_BOB_PUBLIC_KEY_BASE64'
        });

      const resEve = await request(app)
        .post('/api/auth/register')
        .send(userC);
      expect(resEve.status).toBe(201);
      tokenC = resEve.body.token;
    });
  });

  // =========================================================================
  // 2. UPLOAD / DOWNLOAD FLOW WITH MOCK S3 / STORAGE
  // =========================================================================
  describe('2. Upload & Download Metadata Flow (Mock S3 Storage)', () => {
    let mockS3UploadSpy;

    beforeEach(() => {
      // Mock / Spy on storage adapter upload method
      mockS3UploadSpy = jest.spyOn(storage, 'saveEncryptedObject');
    });

    afterEach(() => {
      mockS3UploadSpy.mockRestore();
    });

    test('POST /api/files/upload stores encrypted ciphertext and envelope metadata', async () => {
      // Prepare mock client-side envelope ciphertext (AES-256-GCM)
      const fakeCiphertext = crypto.randomBytes(128); // Pure encrypted bytes
      const fakeIv = crypto.randomBytes(12).toString('hex');
      const fakeDek = crypto.randomBytes(48).toString('base64');
      const fakeSalt = crypto.randomBytes(16).toString('hex');
      const fakeDekIv = crypto.randomBytes(12).toString('base64');

      const res = await request(app)
        .post('/api/files/upload')
        .set('Authorization', `Bearer ${tokenA}`)
        .field('originalName', 'financial_report_2026.pdf')
        .field('mimeType', 'application/pdf')
        .field('size', '1024')
        .field('iv', fakeIv)
        .field('wrappedDEK', fakeDek)
        .field('salt', fakeSalt)
        .field('dekIv', fakeDekIv)
        .attach('file', fakeCiphertext, 'financial_report_2026.pdf.enc');

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('file');
      expect(res.body.file).toHaveProperty('id');
      expect(res.body.file.originalName).toBe('financial_report_2026.pdf');
      expect(res.body.file.iv).toBe(fakeIv);
      expect(res.body.file.wrappedDEK).toBe(fakeDek);

      uploadedFileId = res.body.file.id;

      // Verify that S3 / storage adapter was invoked with ciphertext
      expect(mockS3UploadSpy).toHaveBeenCalledTimes(1);
      const [storageKey, storedBuffer] = mockS3UploadSpy.mock.calls[0];
      expect(storageKey).toMatch(/^zk_file_/);
      expect(storedBuffer).toEqual(fakeCiphertext);
    });

    test('GET /api/files retrieves user file list with envelope metadata', async () => {
      const res = await request(app)
        .get('/api/files')
        .set('Authorization', `Bearer ${tokenA}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('files');
      expect(Array.isArray(res.body.files)).toBe(true);

      const target = res.body.files.find(f => f.id === uploadedFileId);
      expect(target).toBeDefined();
      expect(target.name).toBe('financial_report_2026.pdf');
      expect(target.wrappedDEK).toBeDefined();
      expect(target.iv).toBeDefined();
    });

    test('GET /api/files/:id/download serves raw ciphertext with cryptographic headers', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileId}/download`)
        .set('Authorization', `Bearer ${tokenA}`);

      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/octet-stream');
      expect(res.headers['x-file-iv']).toBeDefined();
      expect(res.headers['x-wrapped-dek']).toBeDefined();
      expect(res.body).toBeInstanceOf(Buffer);
      expect(res.body.length).toBe(128); // Matches the uploaded ciphertext length
    });

    test('GET /api/files/:id/download supports JSON envelope metadata query', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileId}/download?format=json`)
        .set('Authorization', `Bearer ${tokenA}`)
        .set('Accept', 'application/json');

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('base64Ciphertext');
      expect(res.body).toHaveProperty('wrappedDEK');
      expect(res.body).toHaveProperty('iv');
      expect(res.body.fileName).toBe('financial_report_2026.pdf');
    });
  });

  // =========================================================================
  // 3. SHARING ROUTE (/api/files/:id/share)
  // =========================================================================
  describe('3. File Sharing Route (POST /api/files/:id/share)', () => {
    const mockRewrappedDekForBob = 'MOCK_RSA_OAEP_REWRAPPED_DEK_FOR_BOB_BASE64_999==';

    test('Alice (Owner) shares file with Bob by submitting recipient public-key re-wrapped DEK', async () => {
      const res = await request(app)
        .post(`/api/files/${uploadedFileId}/share`)
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          recipientEmail: userB.email,
          wrappedDEK: mockRewrappedDekForBob
        });

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/successfully shared/i);
      expect(res.body.recipient.email).toBe(userB.email);

      // Verify file record in database has recipient in sharedWith list
      const fileRecord = db.findFileById(uploadedFileId);
      expect(fileRecord.sharedWith).toBeDefined();
      const bobEntry = fileRecord.sharedWith.find(s => s.userEmail === userB.email);
      expect(bobEntry).toBeDefined();
      expect(bobEntry.wrappedDEK).toBe(mockRewrappedDekForBob);
    });

    test('Bob (Recipient) can list shared files and access re-wrapped DEK', async () => {
      const res = await request(app)
        .get('/api/files/shared-with-me')
        .set('Authorization', `Bearer ${tokenB}`);

      expect(res.status).toBe(200);
      expect(res.body.files).toBeDefined();
      const sharedFile = res.body.files.find(f => f.id === uploadedFileId);
      expect(sharedFile).toBeDefined();
      expect(sharedFile.wrappedDEK).toBe(mockRewrappedDekForBob);
      expect(sharedFile.ownerEmail).toBe(userA.email);
    });

    test('Bob (Recipient) can download the shared file ciphertext', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileId}/download`)
        .set('Authorization', `Bearer ${tokenB}`);

      expect(res.status).toBe(200);
      expect(res.headers['x-wrapped-dek']).toBe(mockRewrappedDekForBob);
      expect(res.body).toBeInstanceOf(Buffer);
    });

    test('Unauthorized user (Eve) is denied download access (403 Forbidden)', async () => {
      const res = await request(app)
        .get(`/api/files/${uploadedFileId}/download`)
        .set('Authorization', `Bearer ${tokenC}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied|permission/i);
    });

    test('Non-owner cannot share another user\'s file (403 Forbidden)', async () => {
      const res = await request(app)
        .post(`/api/files/${uploadedFileId}/share`)
        .set('Authorization', `Bearer ${tokenC}`)
        .send({
          recipientEmail: userB.email,
          wrappedDEK: 'MALICIOUS_REWRAP'
        });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/access denied|only the file owner/i);
    });
  });

  // =========================================================================
  // 4. ZERO-KNOWLEDGE VERIFICATION: SERVER NEVER RECEIVES PLAINTEXT
  // =========================================================================
  describe('4. Zero-Knowledge Cryptographic Invariant: Server Never Receives Plaintext', () => {
    test('proves that uploaded payload and storage backend receive exclusively high-entropy ciphertext', async () => {
      // 1. Define sensitive plaintext known only to client
      const SECRET_PLAINTEXT = 'TOP_SECRET_PATENT_FORMULA_C8H10N4O2_PLAINTEXT_SECRET_CANARY_VALUE_2026';
      const clientPassword = 'ClientSuperSecretPassword!2026';

      // 2. Perform client-side envelope encryption in the test (simulating browser)
      const secretBlob = new Blob([SECRET_PLAINTEXT], { type: 'text/plain' });
      const envelope = await encryptWithEnvelope(secretBlob, clientPassword);

      // Verify client-side ciphertext does not contain plaintext
      const ciphertextBuffer = Buffer.from(envelope.fileCiphertext);
      expect(ciphertextBuffer.includes(Buffer.from(SECRET_PLAINTEXT))).toBe(false);

      // 3. Upload encrypted package via multipart/form-data to Express server
      const uploadRes = await request(app)
        .post('/api/files/upload')
        .set('Authorization', `Bearer ${tokenA}`)
        .field('originalName', 'classified_formula.txt')
        .field('mimeType', 'text/plain')
        .field('size', SECRET_PLAINTEXT.length.toString())
        .field('iv', Buffer.from(envelope.fileIv).toString('hex'))
        .field('wrappedDEK', Buffer.from(envelope.wrappedDek).toString('base64'))
        .field('salt', Buffer.from(envelope.kekSalt).toString('hex'))
        .field('dekIv', Buffer.from(envelope.dekIv).toString('base64'))
        .attach('file', ciphertextBuffer, 'classified_formula.txt.enc');

      expect(uploadRes.status).toBe(201);
      const secretFileId = uploadRes.body.file.id;

      // 4. Audit server database record
      const dbRecord = db.findFileById(secretFileId);
      expect(dbRecord).toBeDefined();

      // Convert entire DB JSON state to string and assert Canary Plaintext is 100% ABSENT
      const dbJson = JSON.stringify(dbRecord);
      expect(dbJson.includes(SECRET_PLAINTEXT)).toBe(false);

      // 5. Audit actual stored physical file in cloud storage / vault directory
      const rawStoredBytes = storage.getEncryptedObject(dbRecord.storageKey);
      expect(rawStoredBytes).toBeDefined();
      expect(rawStoredBytes.includes(Buffer.from(SECRET_PLAINTEXT))).toBe(false);

      // 6. Audit entire database.json file on disk
      const dbDiskPath = path.resolve(process.cwd(), 'vault_data', 'database.json');
      if (fs.existsSync(dbDiskPath)) {
        const fullDatabaseContents = fs.readFileSync(dbDiskPath, 'utf-8');
        expect(fullDatabaseContents.includes(SECRET_PLAINTEXT)).toBe(false);
      }

      // 7. Verify entropy of stored bytes:
      // AES-256-GCM ciphertext exhibits near-maximum Shannon entropy (~7.5+ bits/byte)
      const byteCounts = new Array(256).fill(0);
      for (let i = 0; i < rawStoredBytes.length; i++) {
        byteCounts[rawStoredBytes[i]]++;
      }
      let entropy = 0;
      for (const count of byteCounts) {
        if (count > 0) {
          const p = count / rawStoredBytes.length;
          entropy -= p * Math.log2(p);
        }
      }
      // For ciphertext of length > 80 bytes, Shannon entropy is typically > 5.5 bits/byte
      expect(entropy).toBeGreaterThan(5.0);
    });
  });
});
