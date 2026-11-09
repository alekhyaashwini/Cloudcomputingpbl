/**
 * @file encryption.js
 * @description Production-grade reusable Web Cryptography API module for browser-based Zero-Knowledge encryption.
 * @standards NIST SP 800-38D (AES-256-GCM) & RFC 8018 (PKCS #5 PBKDF2 v2.1)
 */

export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export async function generateKey(extractable = true) {
  return await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  );
}

export async function encryptFile(file, key) {
  if (!file) throw new Error('encryptFile: A File or Blob object is required.');
  if (!key) throw new Error('encryptFile: A valid CryptoKey is required.');

  const fileBuffer = await file.arrayBuffer();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    fileBuffer
  );

  return { ciphertext, iv };
}

export async function decryptFile(ciphertext, iv, key, mimeType = 'application/octet-stream') {
  if (!ciphertext) throw new Error('decryptFile: Ciphertext ArrayBuffer is required.');
  if (!iv || iv.length !== 12) throw new Error('decryptFile: A 12-byte Uint8Array IV is required.');
  if (!key) throw new Error('decryptFile: A valid CryptoKey is required.');

  try {
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      key,
      ciphertext
    );
    return new Blob([decryptedBuffer], { type: mimeType });
  } catch (err) {
    throw new Error('Decryption Failed: Authentication Tag Mismatch or Incorrect Key!');
  }
}

export async function exportKey(key) {
  const rawBuffer = await window.crypto.subtle.exportKey('raw', key);
  return bufferToBase64(rawBuffer);
}

export async function importKey(base64Key, extractable = true) {
  const rawBuffer = base64ToBuffer(base64Key);
  return await window.crypto.subtle.importKey(
    'raw',
    rawBuffer,
    { name: 'AES-GCM', length: 256 },
    extractable,
    ['encrypt', 'decrypt']
  );
}

export async function deriveKeyFromPassword(password, salt, iterations = 100000) {
  const encoder = new TextEncoder();
  const baseKeyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    baseKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a file using Envelope Encryption:
 * - Generates unique 256-bit DEK for the file
 * - Encrypts file with DEK
 * - Derives KEK from user password via PBKDF2 (100,000 rounds)
 * - Wraps DEK with KEK using AES-256-GCM
 */
export async function encryptWithEnvelope(file, password) {
  if (!file) throw new Error('encryptWithEnvelope: A File or Blob is required.');
  if (!password) throw new Error('encryptWithEnvelope: Master password is required.');

  // 1. Generate unique DEK
  const dek = await generateKey(true);

  // 2. Encrypt file with DEK
  const { ciphertext: fileCiphertext, iv: fileIv } = await encryptFile(file, dek);

  // 3. Generate salt and derive KEK
  const kekSalt = window.crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKeyFromPassword(password, kekSalt, 100000);

  // 4. Wrap DEK with KEK
  const dekIv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrappedDek = await window.crypto.subtle.wrapKey(
    'raw',
    dek,
    kek,
    { name: 'AES-GCM', iv: dekIv, tagLength: 128 }
  );

  return {
    fileCiphertext,
    fileIv,
    wrappedDek,
    dekIv,
    kekSalt,
    metadata: {
      originalName: file.name || 'unnamed_file',
      mimeType: file.type || 'application/octet-stream',
      fileSize: file.size || fileCiphertext.byteLength,
      iterations: 100000,
      algorithm: 'AES-256-GCM',
      kdf: 'PBKDF2-HMAC-SHA256',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Decrypts an envelope package:
 * - Derives KEK from password and salt
 * - Unwraps DEK with KEK (verifies AEAD tag)
 * - Decrypts file using DEK and fileIv
 */
export async function decryptWithEnvelope(encryptedPackage, password) {
  if (!encryptedPackage) throw new Error('decryptWithEnvelope: Package is required.');
  if (!password) throw new Error('decryptWithEnvelope: Password is required.');

  const toBuffer = (val) => {
    if (val instanceof ArrayBuffer) return val;
    if (ArrayBuffer.isView(val)) return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
    if (typeof val === 'string') return base64ToBuffer(val);
    throw new Error('Invalid buffer');
  };

  const toUint8 = (val) => {
    if (val instanceof Uint8Array) return val;
    if (val instanceof ArrayBuffer) return new Uint8Array(val);
    if (typeof val === 'string') return new Uint8Array(base64ToBuffer(val));
    if (Array.isArray(val)) return new Uint8Array(val);
    throw new Error('Invalid byte array');
  };

  const fileCiphertext = toBuffer(encryptedPackage.fileCiphertext);
  const fileIv = toUint8(encryptedPackage.fileIv);
  const wrappedDek = toBuffer(encryptedPackage.wrappedDek);
  const dekIv = toUint8(encryptedPackage.dekIv);
  const kekSalt = toUint8(encryptedPackage.kekSalt);
  const mimeType = encryptedPackage.mimeType || encryptedPackage.metadata?.mimeType || 'application/octet-stream';
  const iterations = encryptedPackage.iterations || encryptedPackage.metadata?.iterations || 100000;

  // 1. Derive KEK
  const kek = await deriveKeyFromPassword(password, kekSalt, iterations);

  // 2. Unwrap DEK
  let unwrappedDek;
  try {
    unwrappedDek = await window.crypto.subtle.unwrapKey(
      'raw',
      wrappedDek,
      kek,
      { name: 'AES-GCM', iv: dekIv, tagLength: 128 },
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  } catch {
    throw new Error('Envelope Decryption Failed: Invalid password or corrupted key envelope!');
  }

  // 3. Decrypt file
  return await decryptFile(fileCiphertext, fileIv, unwrappedDek, mimeType);
}

export function serializeEnvelope(envelope) {
  return {
    fileCiphertext: bufferToBase64(envelope.fileCiphertext),
    fileIv: bufferToBase64(envelope.fileIv.buffer),
    wrappedDek: bufferToBase64(envelope.wrappedDek),
    dekIv: bufferToBase64(envelope.dekIv.buffer),
    kekSalt: bufferToBase64(envelope.kekSalt.buffer),
    metadata: envelope.metadata,
  };
}

export function deserializeEnvelope(serialized) {
  return {
    fileCiphertext: base64ToBuffer(serialized.fileCiphertext),
    fileIv: new Uint8Array(base64ToBuffer(serialized.fileIv)),
    wrappedDek: base64ToBuffer(serialized.wrappedDek),
    dekIv: new Uint8Array(base64ToBuffer(serialized.dekIv)),
    kekSalt: new Uint8Array(base64ToBuffer(serialized.kekSalt)),
    metadata: serialized.metadata,
  };
}

export async function testEncryptionModule() {
  const logs = [];
  const log = (msg) => { logs.push(msg); console.log(`[encryption.js] ${msg}`); };

  try {
    const key = await generateKey();
    log('✓ 1. AES-256-GCM random key generated.');

    const base64Key = await exportKey(key);
    log('✓ 2. Key exported to Base64.');
    const reimportedKey = await importKey(base64Key);
    log('✓ 3. Key imported back from Base64.');

    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKeyFromPassword('PBLSecret2026', salt, 100000);
    log('✓ 4. PBKDF2 Key derived from password (100k rounds).');

    const sampleText = 'Secure Cloud File Storage with Web Crypto API.';
    const sampleBlob = new Blob([sampleText], { type: 'text/plain' });

    const { ciphertext, iv } = await encryptFile(sampleBlob, key);
    log(`✓ 5. Direct file encrypted (IV: 96-bit). Ciphertext length: ${ciphertext.byteLength} bytes.`);

    const decryptedBlob = await decryptFile(ciphertext, iv, key, 'text/plain');
    const decryptedText = await decryptedBlob.text();
    if (decryptedText !== sampleText) throw new Error('Plaintext mismatch!');
    log('✓ 6. Direct decrypted text matches original plaintext.');

    const wrongKey = await generateKey();
    let caughtWrongKey = false;
    try {
      await decryptFile(ciphertext, iv, wrongKey);
    } catch {
      caughtWrongKey = true;
      log('✓ 7. Direct wrong key correctly rejected with tag mismatch error.');
    }
    if (!caughtWrongKey) throw new Error('Failed to reject wrong key!');

    // Envelope tests
    const testPassword = 'PasswordEnvelope2026!';
    const envelope = await encryptWithEnvelope(sampleBlob, testPassword);
    log(`✓ 8. Envelope created with wrapped DEK and file ciphertext.`);

    const envDecrypted = await decryptWithEnvelope(envelope, testPassword);
    const envText = await envDecrypted.text();
    if (envText !== sampleText) throw new Error('Envelope plaintext mismatch!');
    log('✓ 9. Envelope decryption succeeded with correct password.');

    let caughtEnvWrongPass = false;
    try {
      await decryptWithEnvelope(envelope, 'BadPassword');
    } catch {
      caughtEnvWrongPass = true;
      log('✓ 10. Envelope correctly rejected incorrect password.');
    }
    if (!caughtEnvWrongPass) throw new Error('Failed to reject bad password in envelope!');

    return { success: true, logs };
  } catch (err) {
    return { success: false, logs, error: err.message };
  }
}
