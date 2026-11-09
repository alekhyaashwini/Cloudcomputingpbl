/**
 * @file tests/frontend/encryption.test.js
 * @description Frontend Unit Tests for Web Crypto API Zero-Knowledge Module (encryption.js)
 * 
 * Standards & Test Coverage:
 * 1. AES-256-GCM symmetric encryption/decryption round-trip.
 * 2. Envelope encryption correctness (DEK generated, file encrypted, DEK wrapped with KEK).
 * 3. Decryption with incorrect master password fails (PBKDF2/AES-GCM authentication failure).
 * 4. Tampered ciphertext rejection (AES-256-GCM 128-bit authentication tag verification).
 * 5. Multi-user asymmetric sharing (RSA-OAEP DEK re-wrapping and private key decryption).
 */

import '../setup.js';
import {
  generateKey,
  encryptFile,
  decryptFile,
  exportKey,
  importKey,
  deriveKeyFromPassword,
  encryptWithEnvelope,
  decryptWithEnvelope,
  serializeEnvelope,
  deserializeEnvelope,
  generateUserKeyPair,
  exportPublicKey,
  importPublicKey,
  exportPrivateKey,
  importPrivateKey,
  shareFile,
  decryptSharedFile,
  DEFAULT_CHUNK_SIZE,
  encryptFileInChunks,
  decryptFileFromChunks
} from '../../src/services/encryption.js';

describe('Zero-Knowledge Frontend Cryptography (encryption.js)', () => {
  const samplePlainText = 'Confidential College Project: Zero-Knowledge Encrypted Cloud Storage Protocol 2026.';

  // =========================================================================
  // TEST 1: ENCRYPT / DECRYPT ROUND-TRIP
  // =========================================================================
  describe('1. AES-256-GCM Encrypt / Decrypt Round-Trip', () => {
    test('successfully encrypts and decrypts a text file with 100% byte fidelity', async () => {
      const key = await generateKey();
      expect(key).toBeDefined();
      expect(key.algorithm.name).toBe('AES-GCM');

      const originalBlob = new Blob([samplePlainText], { type: 'text/plain' });
      const { ciphertext, iv } = await encryptFile(originalBlob, key);

      expect(ciphertext).toBeInstanceOf(ArrayBuffer);
      expect(ciphertext.byteLength).toBeGreaterThan(samplePlainText.length);
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(12); // NIST 96-bit nonce requirement

      // Decrypt using the same key
      const decryptedBlob = await decryptFile(ciphertext, iv, key, 'text/plain');
      expect(decryptedBlob).toBeInstanceOf(Blob);

      const decryptedText = await decryptedBlob.text();
      expect(decryptedText).toBe(samplePlainText);
    });

    test('generates strictly unique IVs/nonces for consecutive encryptions of the same file', async () => {
      const key = await generateKey();
      const blob = new Blob(['Identical file content for nonce freshness test.'], { type: 'text/plain' });

      const enc1 = await encryptFile(blob, key);
      const enc2 = await encryptFile(blob, key);

      // Verify 96-bit IVs are never identical (prevents catastrophic GCM nonce reuse)
      const iv1Hex = Buffer.from(enc1.iv).toString('hex');
      const iv2Hex = Buffer.from(enc2.iv).toString('hex');
      expect(iv1Hex).not.toBe(iv2Hex);

      // Verify ciphertexts are distinct despite identical plaintext
      const ct1Hex = Buffer.from(enc1.ciphertext).toString('hex');
      const ct2Hex = Buffer.from(enc2.ciphertext).toString('hex');
      expect(ct1Hex).not.toBe(ct2Hex);
    });

    test('supports raw binary buffer preservation (images / binary blobs)', async () => {
      const key = await generateKey();
      const binaryData = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe]);
      const binaryBlob = new Blob([binaryData], { type: 'image/png' });

      const { ciphertext, iv } = await encryptFile(binaryBlob, key);
      const decryptedBlob = await decryptFile(ciphertext, iv, key, 'image/png');
      const decryptedBytes = new Uint8Array(await decryptedBlob.arrayBuffer());

      expect(decryptedBytes).toEqual(binaryData);
    });

    test('key serialization (exportKey / importKey) preserves key material', async () => {
      const originalKey = await generateKey(true);
      const base64Key = await exportKey(originalKey);
      expect(typeof base64Key).toBe('string');

      // Re-import the key from Base64
      const importedKey = await importKey(base64Key);
      expect(importedKey).toBeDefined();

      // Test that imported key successfully decrypts data encrypted by original key
      const blob = new Blob(['Export/Import Key Test'], { type: 'text/plain' });
      const { ciphertext, iv } = await encryptFile(blob, originalKey);

      const decrypted = await decryptFile(ciphertext, iv, importedKey, 'text/plain');
      expect(await decrypted.text()).toBe('Export/Import Key Test');
    });
  });

  // =========================================================================
  // TEST 2: WRONG PASSWORD FAILS
  // =========================================================================
  describe('2. Wrong Password Rejection', () => {
    test('decrypting an envelope-encrypted package with an incorrect password fails', async () => {
      const correctPassword = 'StrongMasterPassword#2026!';
      const wrongPassword = 'IncorrectAttackerPassword#999!';
      const fileBlob = new Blob([samplePlainText], { type: 'text/plain' });

      // Create envelope package
      const envelope = await encryptWithEnvelope(fileBlob, correctPassword);
      expect(envelope).toBeDefined();

      // Attempt decryption with wrong password
      await expect(decryptWithEnvelope(envelope, wrongPassword)).rejects.toThrow(
        /Envelope Decryption Failed|Invalid password|authentication tag failed/i
      );
    });

    test('attempting decryption with slightly varied password fails (case sensitivity)', async () => {
      const password = 'CaseSensitivePassword123';
      const fileBlob = new Blob(['Sensitive case test'], { type: 'text/plain' });
      const envelope = await encryptWithEnvelope(fileBlob, password);

      // Slightly altered password (lowercase 'c')
      await expect(decryptWithEnvelope(envelope, 'caseSensitivePassword123')).rejects.toThrow();
    });
  });

  // =========================================================================
  // TEST 3: ENVELOPE ENCRYPTION CORRECTNESS
  // =========================================================================
  describe('3. Envelope Encryption Correctness', () => {
    test('correctly produces DEK, encrypts payload, and wraps DEK with KEK derived from password', async () => {
      const masterPassword = 'MasterEnvelopeUserPassphrase2026!';
      const fileBlob = new Blob([samplePlainText], { type: 'text/plain' });

      const envelope = await encryptWithEnvelope(fileBlob, masterPassword);

      // Assert cryptographic structure
      expect(envelope).toHaveProperty('fileCiphertext');
      expect(envelope).toHaveProperty('fileIv');
      expect(envelope).toHaveProperty('wrappedDek');
      expect(envelope).toHaveProperty('dekIv');
      expect(envelope).toHaveProperty('kekSalt');
      expect(envelope).toHaveProperty('metadata');

      // Check field specifications
      expect(envelope.fileIv.length).toBe(12); // 96-bit IV
      expect(envelope.dekIv.length).toBe(12);  // 96-bit IV for key wrapping
      expect(envelope.kekSalt.length).toBe(16); // 128-bit salt for PBKDF2
      // 32-byte (256-bit) raw key + 16-byte (128-bit) GCM tag = 48 bytes wrapped DEK
      expect(envelope.wrappedDek.byteLength).toBe(48);

      // Manual verification of envelope mechanics:
      // 1. Re-derive KEK using the exact salt and password
      const kek = await deriveKeyFromPassword(masterPassword, envelope.kekSalt, 100000);
      expect(kek).toBeDefined();

      // 2. Unwrap DEK using KEK
      const unwrappedDek = await window.crypto.subtle.unwrapKey(
        'raw',
        envelope.wrappedDek,
        kek,
        { name: 'AES-GCM', iv: envelope.dekIv, tagLength: 128 },
        { name: 'AES-GCM', length: 256 },
        true,
        ['decrypt']
      );
      expect(unwrappedDek).toBeDefined();

      // 3. Decrypt file ciphertext with unwrapped DEK
      const decryptedBlob = await decryptFile(envelope.fileCiphertext, envelope.fileIv, unwrappedDek, 'text/plain');
      const decryptedContent = await decryptedBlob.text();
      expect(decryptedContent).toBe(samplePlainText);

      // 4. Also assert decryptWithEnvelope helper succeeds
      const helperDecrypted = await decryptWithEnvelope(envelope, masterPassword);
      expect(await helperDecrypted.text()).toBe(samplePlainText);
    });

    test('serializes and deserializes envelope package without data degradation', async () => {
      const password = 'SerializationPassword#456';
      const fileBlob = new Blob(['Payload for JSON serialization test'], { type: 'text/plain' });
      const envelope = await encryptWithEnvelope(fileBlob, password);

      const serialized = serializeEnvelope(envelope);
      expect(typeof serialized.fileCiphertext).toBe('string');
      expect(typeof serialized.wrappedDek).toBe('string');
      expect(typeof serialized.kekSalt).toBe('string');

      const deserialized = deserializeEnvelope(serialized);
      const decrypted = await decryptWithEnvelope(deserialized, password);
      expect(await decrypted.text()).toBe('Payload for JSON serialization test');
    });
  });

  // =========================================================================
  // TEST 4: TAMPERED CIPHERTEXT FAILS AUTHENTICATION (INTEGRITY CHECK)
  // =========================================================================
  describe('4. Tampered Ciphertext Rejection (AES-256-GCM Integrity)', () => {
    test('bit-flip tampering in ciphertext raises authentication tag failure', async () => {
      const key = await generateKey();
      const originalBlob = new Blob([samplePlainText], { type: 'text/plain' });
      const { ciphertext, iv } = await encryptFile(originalBlob, key);

      // Tamper: Flip the first bit of the ciphertext
      const tamperedBytes = new Uint8Array(ciphertext.slice(0));
      tamperedBytes[0] ^= 0x01; // Bit-flip mutation

      // Decryption MUST throw an authentication error and NEVER return corrupted data
      await expect(
        decryptFile(tamperedBytes.buffer, iv, key, 'text/plain')
      ).rejects.toThrow(/Decryption Failed: Authentication Tag Mismatch|OperationError/i);
    });

    test('tampering with the 16-byte authentication tag causes decipher failure', async () => {
      const key = await generateKey();
      const originalBlob = new Blob(['Tag tampering test payload'], { type: 'text/plain' });
      const { ciphertext, iv } = await encryptFile(originalBlob, key);

      // The 128-bit (16 bytes) tag is appended to the end of the ciphertext in Web Crypto AES-GCM
      const tamperedBytes = new Uint8Array(ciphertext.slice(0));
      tamperedBytes[tamperedBytes.length - 1] ^= 0xff; // Invert last byte of tag

      await expect(
        decryptFile(tamperedBytes.buffer, iv, key, 'text/plain')
      ).rejects.toThrow(/Decryption Failed: Authentication Tag Mismatch|OperationError/i);
    });

    test('tampering with the wrapped DEK in an envelope package is detected', async () => {
      const password = 'VaultPassword#789!';
      const fileBlob = new Blob(['Tamper wrapped DEK test'], { type: 'text/plain' });
      const envelope = await encryptWithEnvelope(fileBlob, password);

      // Tamper wrapped DEK byte
      const corruptedWrappedDek = new Uint8Array(envelope.wrappedDek.slice(0));
      corruptedWrappedDek[5] ^= 0x55;

      const tamperedEnvelope = {
        ...envelope,
        wrappedDek: corruptedWrappedDek.buffer
      };

      await expect(decryptWithEnvelope(tamperedEnvelope, password)).rejects.toThrow(
        /Envelope Decryption Failed|authentication tag failed/i
      );
    });
  });

  // =========================================================================
  // TEST 5: ZERO-KNOWLEDGE RSA-OAEP MULTI-USER SHARING
  // =========================================================================
  describe('5. Asymmetric RSA-OAEP Multi-User Sharing Flow', () => {
    test('owner can re-wrap DEK with recipient public key, and recipient can decrypt file', async () => {
      const ownerPassword = 'AliceMasterPassword!2026';
      const fileBlob = new Blob(['Zero-Knowledge Shared Research Paper'], { type: 'text/plain' });

      // Alice creates envelope-encrypted file
      const aliceEnvelope = await encryptWithEnvelope(fileBlob, ownerPassword);

      // Bob generates an RSA-OAEP 2048-bit key pair
      const bobKeyPair = await generateUserKeyPair();
      const bobPublicKeyBase64 = await exportPublicKey(bobKeyPair.publicKey);
      expect(typeof bobPublicKeyBase64).toBe('string');

      // Alice shares the file with Bob by re-wrapping DEK with Bob's public key
      const shareResult = await shareFile(
        {
          fileId: 'file_research_101',
          wrappedDek: aliceEnvelope.wrappedDek,
          dekIv: aliceEnvelope.dekIv,
          kekSalt: aliceEnvelope.kekSalt
        },
        bobPublicKeyBase64,
        ownerPassword
      );

      expect(shareResult).toHaveProperty('recipientWrappedDek');
      expect(typeof shareResult.recipientWrappedDek).toBe('string');

      // Bob downloads the shared package and decrypts it using his private key
      const bobSharedPackage = {
        fileCiphertext: aliceEnvelope.fileCiphertext,
        fileIv: aliceEnvelope.fileIv,
        wrappedDek: shareResult.recipientWrappedDek,
        mimeType: 'text/plain'
      };

      const bobDecryptedBlob = await decryptSharedFile(bobSharedPackage, bobKeyPair.privateKey);
      const bobDecryptedText = await bobDecryptedBlob.text();
      expect(bobDecryptedText).toBe('Zero-Knowledge Shared Research Paper');
    });

    test('unauthorized third-party (Eve) cannot decrypt Bob\'s shared package', async () => {
      const ownerPassword = 'AlicePassword#123';
      const fileBlob = new Blob(['Top Secret Document'], { type: 'text/plain' });
      const aliceEnvelope = await encryptWithEnvelope(fileBlob, ownerPassword);

      const bobKeyPair = await generateUserKeyPair();
      const eveKeyPair = await generateUserKeyPair(); // Adversary
      const bobPublicKeyBase64 = await exportPublicKey(bobKeyPair.publicKey);

      const shareResult = await shareFile(
        {
          fileId: 'file_secret_202',
          wrappedDek: aliceEnvelope.wrappedDek,
          dekIv: aliceEnvelope.dekIv,
          kekSalt: aliceEnvelope.kekSalt
        },
        bobPublicKeyBase64,
        ownerPassword
      );

      const bobSharedPackage = {
        fileCiphertext: aliceEnvelope.fileCiphertext,
        fileIv: aliceEnvelope.fileIv,
        wrappedDek: shareResult.recipientWrappedDek,
        mimeType: 'text/plain'
      };

      // Eve attempts decryption with Eve's private key -> MUST fail
      await expect(decryptSharedFile(bobSharedPackage, eveKeyPair.privateKey)).rejects.toThrow();
    });
  });

  // =========================================================================
  // TEST 6: CHUNKED ENCRYPTION FOR LARGE FILES (5 MB CHUNKS)
  // =========================================================================
  describe('6. Chunked Large File Encryption & Manifest Protocol', () => {
    test('splits a file into chunks, generates dedicated IVs per chunk, and round-trips with 100% fidelity', async () => {
      const password = 'ChunkedPassword#2026!';
      // Create a test file of 128 KB (using smaller 32 KB chunk size for rapid testing)
      const testChunkSize = 32 * 1024; // 32 KB chunks
      const repeatedPattern = 'ZeroKnowledgeLargeFileChunkData-2026#'.repeat(3000); // ~110 KB
      const sourceBlob = new Blob([repeatedPattern], { type: 'text/plain' });

      // 1. Encrypt in chunks
      const { manifest, chunks } = await encryptFileInChunks(sourceBlob, password, {
        chunkSize: testChunkSize,
      });

      expect(manifest).toBeDefined();
      expect(manifest.schema).toBe('zero-knowledge-chunked-manifest-v1');
      expect(manifest.totalChunks).toBe(Math.ceil(sourceBlob.size / testChunkSize));
      expect(manifest.chunks.length).toBe(manifest.totalChunks);
      expect(chunks.length).toBe(manifest.totalChunks);

      // Verify each chunk has an independent, unique IV
      const ivSet = new Set(manifest.chunks.map(c => c.iv));
      expect(ivSet.size).toBe(manifest.totalChunks);

      // Verify each encrypted chunk includes ciphertext + 128-bit (16-byte) auth tag
      for (let i = 0; i < chunks.length; i++) {
        const expectedSize = manifest.chunks[i].size + 16;
        expect(chunks[i].byteLength).toBe(expectedSize);
      }

      // 2. Decrypt using the manifest and chunks
      const decryptedBlob = await decryptFileFromChunks(manifest, chunks, password);
      expect(decryptedBlob).toBeInstanceOf(Blob);

      const decryptedText = await decryptedBlob.text();
      expect(decryptedText).toBe(repeatedPattern);
      expect(decryptedBlob.size).toBe(sourceBlob.size);
    });

    test('tampering with any single chunk causes authenticated decryption failure', async () => {
      const password = 'TamperDetectPassword#123!';
      const sourceBlob = new Blob(['ChunkOneContent-AAAA' + 'ChunkTwoContent-BBBB'], { type: 'text/plain' });
      const testChunkSize = 20; // 20 bytes per chunk -> 2 chunks

      const { manifest, chunks } = await encryptFileInChunks(sourceBlob, password, {
        chunkSize: testChunkSize,
      });

      expect(chunks.length).toBeGreaterThanOrEqual(2);

      // Tamper with chunk 1: Flip a byte in the ciphertext
      const tamperedChunkBytes = new Uint8Array(chunks[1].slice(0));
      tamperedChunkBytes[0] ^= 0xff; // Invert first byte

      const corruptedChunks = [chunks[0], tamperedChunkBytes.buffer];

      // Decryption MUST throw an integrity verification error
      await expect(
        decryptFileFromChunks(manifest, corruptedChunks, password)
      ).rejects.toThrow(/Integrity verification failed on chunk #1/);
    });

    test('decrypting chunks with wrong password fails to unwrap DEK', async () => {
      const sourceBlob = new Blob(['Top Secret Blueprint'], { type: 'text/plain' });
      const { manifest, chunks } = await encryptFileInChunks(sourceBlob, 'CorrectPass#123', {
        chunkSize: 10,
      });

      await expect(
        decryptFileFromChunks(manifest, chunks, 'WrongPass#999')
      ).rejects.toThrow(/Authentication failed/);
    });
  });
});

