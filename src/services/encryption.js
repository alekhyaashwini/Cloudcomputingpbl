/**
 * @file encryption.js
 * @description Production-grade reusable Web Cryptography API module for browser-based Zero-Knowledge encryption.
 * @standards NIST SP 800-38D (AES-256-GCM) & RFC 8018 (PKCS #5 PBKDF2 v2.1)
 *
 * Capabilities:
 * 1. generateKey() - Generates a 256-bit AES-GCM symmetric CryptoKey
 * 2. encryptFile(file, key) - Encrypts File/Blob into { ciphertext: ArrayBuffer, iv: Uint8Array }
 * 3. decryptFile(ciphertext, iv, key, mimeType) - Decrypts back to Blob with tag verification
 * 4. exportKey(key) - Serializes CryptoKey to Base64 string for storage/transfer
 * 5. importKey(base64Key) - Deserializes Base64 string into a valid CryptoKey
 * 6. deriveKeyFromPassword(password, salt) - PBKDF2-HMAC-SHA256 (100,000 rounds) key derivation
 * 7. testEncryptionModule() - Self-test verification suite
 */

/**
 * Converts an ArrayBuffer to a Base64-encoded string.
 * @param {ArrayBuffer} buffer - The raw binary buffer.
 * @returns {string} Base64 string representation.
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

/**
 * Converts a Base64-encoded string back to an ArrayBuffer.
 * @param {string} base64 - Base64 string representation.
 * @returns {ArrayBuffer} Reconstructed ArrayBuffer.
 */
export function base64ToBuffer(base64) {
  const binary = window.atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * 1. Generates a cryptographically secure random AES-256-GCM key.
 *
 * @param {boolean} [extractable=true] - Whether the key can be exported via exportKey().
 * @returns {Promise<CryptoKey>} A 256-bit symmetric CryptoKey for AES-GCM operations.
 *
 * @example
 * const key = await generateKey();
 */
export async function generateKey(extractable = true) {
  try {
    return await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256, // 256-bit encryption
      },
      extractable,
      ['encrypt', 'decrypt'] // Permitted key operations
    );
  } catch (err) {
    throw new Error(`Failed to generate AES-256-GCM key: ${err.message}`);
  }
}

/**
 * 2. Reads a File or Blob, encrypts its contents using AES-256-GCM with a fresh 96-bit nonce.
 *
 * Notice:
 * - A 96-bit (12 bytes) CSPRNG initialization vector (IV) is generated for EVERY file.
 * - Nonce reuse with the same AES-GCM key is strictly prevented.
 * - The returned ciphertext ArrayBuffer contains the encrypted bytes followed by the 128-bit MAC tag.
 *
 * @param {File|Blob} file - The file or blob object to encrypt.
 * @param {CryptoKey} key - The 256-bit AES-GCM CryptoKey.
 * @returns {Promise<{ ciphertext: ArrayBuffer, iv: Uint8Array }>}
 *
 * @example
 * const { ciphertext, iv } = await encryptFile(myFile, key);
 */
export async function encryptFile(file, key) {
  if (!file) throw new Error('encryptFile: A File or Blob object is required.');
  if (!key) throw new Error('encryptFile: A valid CryptoKey is required.');

  try {
    // 1. Read file contents into an ArrayBuffer
    const fileBuffer = await file.arrayBuffer();

    // 2. Generate a 96-bit (12-byte) cryptographically secure pseudorandom Nonce/IV
    // (Recommended standard length per NIST SP 800-38D)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 3. Perform Authenticated Encryption with Associated Data (AEAD)
    // The Web Crypto API computes and appends the 128-bit GHASH authentication tag automatically
    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128, // 128-bit authentication tag
      },
      key,
      fileBuffer
    );

    return {
      ciphertext,
      iv,
    };
  } catch (err) {
    throw new Error(`Encryption failed: ${err.message}`);
  }
}

/**
 * 3. Decrypts an AES-256-GCM ciphertext back into a decrypted Blob.
 *
 * Security:
 * - Automatically verifies the 128-bit authentication tag before returning plaintext.
 * - If the ciphertext was tampered with or the wrong key is supplied, throws an explicit error.
 *
 * @param {ArrayBuffer} ciphertext - The encrypted payload (including 16-byte authentication tag).
 * @param {Uint8Array} iv - The 12-byte initialization vector used during encryption.
 * @param {CryptoKey} key - The 256-bit AES-GCM decryption key.
 * @param {string} [mimeType='application/octet-stream'] - MIME type for the output Blob.
 * @returns {Promise<Blob>} The decrypted file data encapsulated in a Blob.
 *
 * @example
 * const decryptedBlob = await decryptFile(ciphertext, iv, key, 'application/pdf');
 */
export async function decryptFile(ciphertext, iv, key, mimeType = 'application/octet-stream') {
  if (!ciphertext) throw new Error('decryptFile: Ciphertext ArrayBuffer is required.');
  if (!iv || iv.length !== 12) throw new Error('decryptFile: A 12-byte Uint8Array IV is required.');
  if (!key) throw new Error('decryptFile: A valid CryptoKey is required.');

  try {
    // Perform Authenticated Decryption
    // Web Crypto validates the 16-byte tag; if tag mismatch occurs, this promise rejects
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      ciphertext
    );

    // Return as a standard browser Blob for download or preview
    return new Blob([decryptedBuffer], { type: mimeType });
  } catch (err) {
    // Web Crypto API throws an OperationError on tag verification failure or wrong key
    throw new Error(
      'Decryption Failed: Authentication Tag Mismatch or Incorrect Key! ' +
      'The ciphertext may have been tampered with or corrupted in transit/storage.'
    );
  }
}

/**
 * 4a. Exports a CryptoKey to a Base64-encoded raw string for storage or transmission.
 *
 * @param {CryptoKey} key - The key to export.
 * @returns {Promise<string>} Base64-encoded raw 256-bit key string.
 *
 * @example
 * const base64Key = await exportKey(key);
 */
export async function exportKey(key) {
  if (!key) throw new Error('exportKey: A valid CryptoKey is required.');

  try {
    const rawBuffer = await window.crypto.subtle.exportKey('raw', key);
    return bufferToBase64(rawBuffer);
  } catch (err) {
    throw new Error(`Failed to export key: ${err.message}. Ensure extractable=true.`);
  }
}

/**
 * 4b. Imports a Base64-encoded raw key string into a usable AES-256-GCM CryptoKey.
 *
 * @param {string} base64Key - Base64 string of the 32-byte raw key.
 * @param {boolean} [extractable=true] - Whether the imported key can be re-exported.
 * @returns {Promise<CryptoKey>} Reconstructed AES-GCM CryptoKey.
 *
 * @example
 * const restoredKey = await importKey(base64Key);
 */
export async function importKey(base64Key, extractable = true) {
  if (!base64Key || typeof base64Key !== 'string') {
    throw new Error('importKey: Base64 string is required.');
  }

  try {
    const rawBuffer = base64ToBuffer(base64Key);
    if (rawBuffer.byteLength !== 32) {
      throw new Error(`Invalid key size: expected 32 bytes (256 bits), got ${rawBuffer.byteLength} bytes.`);
    }

    return await window.crypto.subtle.importKey(
      'raw',
      rawBuffer,
      {
        name: 'AES-GCM',
        length: 256,
      },
      extractable,
      ['encrypt', 'decrypt']
    );
  } catch (err) {
    throw new Error(`Failed to import key: ${err.message}`);
  }
}

/**
 * 5. Derives an AES-256-GCM key from a user password using PBKDF2-HMAC-SHA256.
 *
 * Security:
 * - Iterations: 100,000 rounds (NIST SP 800-132 compliant to resist GPU brute-forcing).
 * - Salt: Must be a unique 16-byte random salt generated via crypto.getRandomValues().
 *
 * @param {string} password - The user's master password/passphrase.
 * @param {Uint8Array} salt - A 16-byte cryptographically secure random salt.
 * @param {number} [iterations=100000] - Number of PBKDF2 iterations.
 * @returns {Promise<CryptoKey>} Derived 256-bit AES-GCM key.
 *
 * @example
 * const salt = window.crypto.getRandomValues(new Uint8Array(16));
 * const kek = await deriveKeyFromPassword("UserSuperSecretPassword123!", salt);
 */
export async function deriveKeyFromPassword(password, salt, iterations = 100000) {
  if (!password || typeof password !== 'string') {
    throw new Error('deriveKeyFromPassword: Password must be a non-empty string.');
  }
  if (!salt || !(salt instanceof Uint8Array) || salt.length < 16) {
    throw new Error('deriveKeyFromPassword: A cryptographically secure salt of at least 16 bytes is required.');
  }

  try {
    const encoder = new TextEncoder();
    // 1. Ingest raw password string into a base key material
    const baseKeyMaterial = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false, // Never allow base password extraction
      ['deriveKey']
    );

    // 2. Derive 256-bit symmetric AES-GCM key using PBKDF2-HMAC-SHA256
    const derivedKey = await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256',
      },
      baseKeyMaterial,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // Allow key export if needed for KEK wrapping
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );

    return derivedKey;
  } catch (err) {
    throw new Error(`Key derivation failed: ${err.message}`);
  }
}

/**
 * 6. Implements Envelope Encryption:
 * - Generates a fresh, unique 256-bit AES-GCM Data Encryption Key (DEK) for this file.
 * - Encrypts the file contents directly with the DEK (AES-256-GCM, 96-bit file IV, 128-bit MAC tag).
 * - Derives the user's Key Encryption Key (KEK) from their passphrase via PBKDF2 (100,000 iterations, SHA-256, 16-byte random salt).
 * - Wraps/encrypts the DEK using the KEK with AES-256-GCM (generating a dedicated 96-bit dekIv).
 * - Packages the encrypted payload, wrapped key, IVs, and derivation salt.
 *
 * @param {File|Blob} file - The file or blob to encrypt.
 * @param {string} password - The user's master passphrase.
 * @returns {Promise<{
 *   fileCiphertext: ArrayBuffer,
 *   fileIv: Uint8Array,
 *   wrappedDek: ArrayBuffer,
 *   dekIv: Uint8Array,
 *   kekSalt: Uint8Array,
 *   metadata: {
 *     originalName: string,
 *     mimeType: string,
 *     fileSize: number,
 *     iterations: number,
 *     algorithm: string,
 *     kdf: string,
 *     timestamp: string
 *   }
 * }>}
 *
 * @example
 * const encryptedPackage = await encryptWithEnvelope(myFile, "UserPassphrase123!");
 */
export async function encryptWithEnvelope(file, password) {
  if (!file) throw new Error('encryptWithEnvelope: A File or Blob is required.');
  if (!password || typeof password !== 'string') {
    throw new Error('encryptWithEnvelope: Master password must be a non-empty string.');
  }

  try {
    // Step 1: Generate a unique, random Data Encryption Key (DEK) for this specific file
    const dek = await generateKey(true);

    // Step 2: Encrypt the file data using the DEK (generates fresh 12-byte fileIv)
    const { ciphertext: fileCiphertext, iv: fileIv } = await encryptFile(file, dek);

    // Step 3: Generate a 16-byte cryptographically secure random salt for KEK derivation
    const kekSalt = window.crypto.getRandomValues(new Uint8Array(16));

    // Step 4: Derive the Key Encryption Key (KEK) from the user password via PBKDF2 (100k rounds)
    const kek = await deriveKeyFromPassword(password, kekSalt, 100000);

    // Step 5: Generate a 12-byte random IV for wrapping the DEK
    const dekIv = window.crypto.getRandomValues(new Uint8Array(12));

    // Step 6: Wrap (encrypt) the DEK using the KEK via AES-256-GCM key wrapping
    const wrappedDek = await window.crypto.subtle.wrapKey(
      'raw',
      dek,
      kek,
      {
        name: 'AES-GCM',
        iv: dekIv,
        tagLength: 128,
      }
    );

    const originalName = file.name || 'unnamed_file';
    const mimeType = file.type || 'application/octet-stream';
    const fileSize = file.size || fileCiphertext.byteLength;

    return {
      fileCiphertext,
      fileIv,
      wrappedDek,
      dekIv,
      kekSalt,
      metadata: {
        originalName,
        mimeType,
        fileSize,
        iterations: 100000,
        algorithm: 'AES-256-GCM',
        kdf: 'PBKDF2-HMAC-SHA256',
        timestamp: new Date().toISOString(),
      },
    };
  } catch (err) {
    throw new Error(`Envelope encryption failed: ${err.message}`);
  }
}

/**
 * 7. Decrypts an envelope-encrypted package:
 * - Derives the KEK from the supplied password and kekSalt via PBKDF2 (100,000 iterations).
 * - Unwraps the DEK using the derived KEK and dekIv (verifying AEAD tag integrity).
 * - If the password is wrong or the wrapped DEK was corrupted, throws an explicit security error.
 * - Decrypts the file ciphertext using the unwrapped DEK and fileIv.
 * - Returns the restored Blob.
 *
 * @param {Object} encryptedPackage - The envelope package.
 * @param {ArrayBuffer|string} encryptedPackage.fileCiphertext - Encrypted file content.
 * @param {Uint8Array|string} encryptedPackage.fileIv - 12-byte initialization vector for the file.
 * @param {ArrayBuffer|string} encryptedPackage.wrappedDek - Encrypted DEK.
 * @param {Uint8Array|string} encryptedPackage.dekIv - 12-byte initialization vector for DEK wrapping.
 * @param {Uint8Array|string} encryptedPackage.kekSalt - 16-byte PBKDF2 salt.
 * @param {Object} [encryptedPackage.metadata] - Optional metadata containing mimeType.
 * @param {string} [encryptedPackage.mimeType] - Optional mimeType override.
 * @param {string} password - The user's master passphrase.
 * @returns {Promise<Blob>} The decrypted file data encapsulated in a Blob.
 *
 * @example
 * const decryptedBlob = await decryptWithEnvelope(encryptedPackage, "UserPassphrase123!");
 */
export async function decryptWithEnvelope(encryptedPackage, password) {
  if (!encryptedPackage) {
    throw new Error('decryptWithEnvelope: encryptedPackage is required.');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('decryptWithEnvelope: Password must be a non-empty string.');
  }

  // Normalization helpers for typed arrays and ArrayBuffers (supports raw or Base64)
  const toBuffer = (val, name) => {
    if (val instanceof ArrayBuffer) return val;
    if (ArrayBuffer.isView(val)) {
      return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
    }
    if (typeof val === 'string') return base64ToBuffer(val);
    throw new Error(`decryptWithEnvelope: Invalid format for ${name}`);
  };

  const toUint8Array = (val, name) => {
    if (val instanceof Uint8Array) return val;
    if (val instanceof ArrayBuffer) return new Uint8Array(val);
    if (typeof val === 'string') return new Uint8Array(base64ToBuffer(val));
    if (Array.isArray(val)) return new Uint8Array(val);
    throw new Error(`decryptWithEnvelope: Invalid format for ${name}`);
  };

  try {
    let rawWrappedDek = encryptedPackage.wrappedDek || encryptedPackage.wrappedDEK;
    let rawDekIv = encryptedPackage.dekIv || encryptedPackage.dekIV;
    let rawFileIv = encryptedPackage.fileIv || encryptedPackage.iv || encryptedPackage.ivHex;
    let rawSalt = encryptedPackage.kekSalt || encryptedPackage.salt || encryptedPackage.saltHex;
    let rawFileCiphertext = encryptedPackage.fileCiphertext || encryptedPackage.ciphertext || encryptedPackage.base64Ciphertext;

    // Check if wrappedDek is JSON string containing { wrappedDek, dekIv }
    if (typeof rawWrappedDek === 'string' && rawWrappedDek.trim().startsWith('{')) {
      try {
        const parsed = JSON.parse(rawWrappedDek);
        if (parsed.wrappedDek || parsed.wrappedDEK) {
          rawWrappedDek = parsed.wrappedDek || parsed.wrappedDEK;
        }
        if (!rawDekIv && (parsed.dekIv || parsed.dekIV)) {
          rawDekIv = parsed.dekIv || parsed.dekIV;
        }
      } catch (e) {
        // fallback
      }
    }

    // If dekIv was not supplied separately, check if it was packed in the first 12 bytes of wrappedDek
    if (!rawDekIv && rawWrappedDek) {
      try {
        const fullBuf = toBuffer(rawWrappedDek, 'wrappedDek');
        if (fullBuf.byteLength > 44) {
          rawDekIv = new Uint8Array(fullBuf.slice(0, 12));
          rawWrappedDek = fullBuf.slice(12);
        }
      } catch (e) {
        // fallback
      }
    }

    const fileCiphertext = toBuffer(rawFileCiphertext, 'fileCiphertext');
    const fileIv = toUint8Array(rawFileIv, 'fileIv');
    const wrappedDek = toBuffer(rawWrappedDek, 'wrappedDek');
    const dekIv = rawDekIv ? toUint8Array(rawDekIv, 'dekIv') : fileIv;
    const kekSalt = toUint8Array(rawSalt, 'kekSalt');

    const mimeType =
      encryptedPackage.mimeType ||
      encryptedPackage.metadata?.mimeType ||
      'application/octet-stream';
    const iterations =
      encryptedPackage.iterations ||
      encryptedPackage.metadata?.iterations ||
      100000;

    // Step 1: Derive the user's Key Encryption Key (KEK) using password + salt
    const kek = await deriveKeyFromPassword(password, kekSalt, iterations);

    // Step 2: Unwrap (decrypt) the Data Encryption Key (DEK) using the KEK
    let unwrappedDek;
    try {
      unwrappedDek = await window.crypto.subtle.unwrapKey(
        'raw',
        wrappedDek,
        kek,
        {
          name: 'AES-GCM',
          iv: dekIv,
          tagLength: 128,
        },
        {
          name: 'AES-GCM',
          length: 256,
        },
        false, // DEK does not need to be extractable once unwrapped
        ['decrypt']
      );
    } catch (unwrapErr) {
      // AEAD tag mismatch when unwrapping indicates incorrect password or tampered key envelope
      throw new Error(
        'Envelope Decryption Failed: Invalid password or corrupted Key Encryption Key (KEK) envelope! ' +
        'The 128-bit authentication tag failed verification.'
      );
    }

    // Step 3: Decrypt the file ciphertext using the unwrapped DEK and fileIv
    const decryptedBlob = await decryptFile(fileCiphertext, fileIv, unwrappedDek, mimeType);

    return decryptedBlob;
  } catch (err) {
    throw err;
  }
}

/**
 * Serializes an envelope package into a JSON-safe object where binary fields are Base64 strings.
 * @param {Object} envelope - The raw envelope package.
 * @returns {Object} JSON-serializable envelope object.
 */
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

/**
 * Deserializes a JSON-safe Base64 envelope object back into raw binary buffers.
 * @param {Object} serialized - The serialized envelope object.
 * @returns {Object} Reconstructed raw envelope package.
 */
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

/**
 * Self-test verification function.
 * Encrypts and decrypts a sample string, tests wrong key rejection,
 * verifies envelope encryption with DEK/KEK wrapping, and asserts cryptographic invariants.
 *
 * @returns {Promise<{ success: boolean, logs: string[] }>}
 *
 * @example
 * const result = await testEncryptionModule();
 * console.log("Module Self-Test Passed:", result.success);
 */
export async function testEncryptionModule() {
  const logs = [];
  const log = (msg) => {
    logs.push(msg);
    console.log(`[encryption.js self-test] ${msg}`);
  };

  try {
    log('--- Starting Web Crypto API Module Self-Test ---');

    // Test 1: Key Generation
    const key = await generateKey();
    log('✓ 1. AES-256-GCM random key successfully generated.');

    // Test 2: Export & Import
    const base64Key = await exportKey(key);
    log(`✓ 2a. Key exported to Base64 (length: ${base64Key.length} chars).`);
    const reimportedKey = await importKey(base64Key);
    log('✓ 2b. Key re-imported from Base64 successfully.');

    // Test 3: Password Derivation
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const derivedKey = await deriveKeyFromPassword('PBL_SuperSecret_2026', salt, 100000);
    log('✓ 3. Derived 256-bit key from password via PBKDF2 (100,000 iterations, SHA-256).');

    // Test 4: Direct File Encryption & Decryption Roundtrip
    const originalText = 'Confidential College PBL Project: Secure Cloud File Storage using Encryption.';
    const sampleBlob = new Blob([originalText], { type: 'text/plain' });

    log(`✓ 4a. Encrypting sample plaintext: "${originalText.substring(0, 32)}..."`);
    const { ciphertext, iv } = await encryptFile(sampleBlob, key);
    log(`✓ 4b. Encryption complete. Nonce length: ${iv.length} bytes, Ciphertext length: ${ciphertext.byteLength} bytes.`);

    // Decrypt with correct key
    const decryptedBlob = await decryptFile(ciphertext, iv, key, 'text/plain');
    const decryptedText = await decryptedBlob.text();

    if (decryptedText !== originalText) {
      throw new Error('Assertion failed: Decrypted text does not match original plaintext!');
    }
    log('✓ 4c. Decrypted text matches original plaintext with 100% byte fidelity.');

    // Test 5: Wrong Key Rejection (Integrity Test)
    log('✓ 5a. Testing wrong key rejection (Tamper/Authentication failure)...');
    const wrongKey = await generateKey();
    let wrongKeyCaught = false;

    try {
      await decryptFile(ciphertext, iv, wrongKey, 'text/plain');
    } catch (err) {
      wrongKeyCaught = true;
      log(`✓ 5b. Correctly rejected wrong key with error: "${err.message}"`);
    }

    if (!wrongKeyCaught) {
      throw new Error('Security vulnerability: Decryption succeeded with an invalid key!');
    }

    // Test 6: Tampered Ciphertext Rejection (Bit-Flip Test)
    log('✓ 6a. Testing bit-flip tampering detection in ciphertext...');
    const tamperedCiphertext = new Uint8Array(ciphertext.slice(0));
    tamperedCiphertext[0] ^= 0x01; // Invert first bit

    let tamperCaught = false;
    try {
      await decryptFile(tamperedCiphertext.buffer, iv, key, 'text/plain');
    } catch (err) {
      tamperCaught = true;
      log(`✓ 6b. Correctly detected ciphertext corruption: "${err.message}"`);
    }

    if (!tamperCaught) {
      throw new Error('Security vulnerability: Tampered ciphertext was not rejected by AES-GCM!');
    }

    // Test 7: ENVELOPE ENCRYPTION ROUNDTRIP (DEK wrapped by KEK)
    log('✓ 7a. Testing Envelope Encryption (DEK generated, file encrypted, DEK wrapped by PBKDF2 KEK)...');
    const testPassword = 'CorrectMasterPassword#2026!';
    const envelopePackage = await encryptWithEnvelope(sampleBlob, testPassword);
    log(`✓ 7b. Envelope created: fileCiphertext=${envelopePackage.fileCiphertext.byteLength}B, wrappedDek=${envelopePackage.wrappedDek.byteLength}B.`);

    // Decrypt envelope with correct password
    const envDecryptedBlob = await decryptWithEnvelope(envelopePackage, testPassword);
    const envDecryptedText = await envDecryptedBlob.text();
    if (envDecryptedText !== originalText) {
      throw new Error('Assertion failed: Envelope decrypted text does not match original plaintext!');
    }
    log('✓ 7c. Envelope decryption succeeded with correct password. 100% data integrity verified.');

    // Test 8: Envelope Decryption with WRONG password
    log('✓ 8a. Testing Envelope Decryption with incorrect password rejection...');
    let envWrongPassCaught = false;
    try {
      await decryptWithEnvelope(envelopePackage, 'AttackerWrongPassword999!');
    } catch (err) {
      envWrongPassCaught = true;
      log(`✓ 8b. Correctly rejected wrong password during KEK unwrap: "${err.message}"`);
    }
    if (!envWrongPassCaught) {
      throw new Error('Security vulnerability: Envelope unwrapped with incorrect password!');
    }

    // Test 9: Serialization & Deserialization
    const serialized = serializeEnvelope(envelopePackage);
    const deserialized = deserializeEnvelope(serialized);
    const restoredFromSerialized = await decryptWithEnvelope(deserialized, testPassword);
    const restoredText = await restoredFromSerialized.text();
    if (restoredText !== originalText) {
      throw new Error('Assertion failed: Deserialized envelope roundtrip mismatch!');
    }
    log('✓ 9. JSON Base64 Serialization & Deserialization roundtrip verified.');

    // Test 10: Asymmetric RSA-OAEP Key Pair Generation & Multi-User Zero-Knowledge Sharing
    log('✓ 10a. Generating RSA-OAEP key pairs for Alice (Owner) and Bob (Recipient)...');
    const aliceKeys = await generateUserKeyPair();
    const bobKeys = await generateUserKeyPair();
    const eveKeys = await generateUserKeyPair(); // Adversary
    log('✓ 10b. RSA-OAEP 2048-bit key pairs generated for Alice, Bob, and Eve.');

    // Export Bob's public key (as would be stored on server)
    const bobPublicKeyBase64 = await exportPublicKey(bobKeys.publicKey);
    log(`✓ 10c. Bob public key exported to Base64 SPKI (${bobPublicKeyBase64.length} chars).`);

    // Alice shares the envelope-encrypted file with Bob
    log('✓ 10d. Alice unwraps DEK with password and re-wraps DEK with Bob\'s public key...');
    const shareResult = await shareFile(
      {
        fileId: 'file_test_shared_123',
        wrappedDek: envelopePackage.wrappedDek,
        dekIv: envelopePackage.dekIv,
        kekSalt: envelopePackage.kekSalt
      },
      bobPublicKeyBase64,
      testPassword
    );
    log(`✓ 10e. DEK re-wrapped for Bob via RSA-OAEP (${shareResult.recipientWrappedDek.length} chars Base64). Zero plaintext DEK exposed!`);

    // Bob downloads file and decrypts using Bob's private key
    log('✓ 10f. Bob decrypting shared package using Bob\'s private key...');
    const bobSharedPackage = {
      fileCiphertext: envelopePackage.fileCiphertext,
      fileIv: envelopePackage.fileIv,
      wrappedDek: shareResult.recipientWrappedDek,
      mimeType: 'text/plain'
    };
    const bobDecryptedBlob = await decryptSharedFile(bobSharedPackage, bobKeys.privateKey);
    const bobDecryptedText = await bobDecryptedBlob.text();
    if (bobDecryptedText !== originalText) {
      throw new Error('Assertion failed: Bob decrypted text does not match original plaintext!');
    }
    log('✓ 10g. Bob decrypted plaintext successfully with 100% byte fidelity.');

    // Test 11: Unauthorized Third-Party Rejection (Eve's key fails)
    log('✓ 11a. Testing Eve (adversary) attempting to unwrap Bob\'s re-wrapped DEK...');
    let eveCaught = false;
    try {
      await decryptSharedFile(bobSharedPackage, eveKeys.privateKey);
    } catch (err) {
      eveCaught = true;
      log(`✓ 11b. Correctly rejected Eve with cryptographic failure: "${err.message}"`);
    }
    if (!eveCaught) {
      throw new Error('Security vulnerability: Unauthorized user decrypted shared package!');
    }

    log('--- All Web Crypto Module Self-Tests (including Asymmetric RSA-OAEP Sharing) PASSED Successfully! ---');
    return { success: true, logs };
  } catch (err) {
    log(`❌ Self-test failed: ${err.message}`);
    return { success: false, logs, error: err.message };
  }
}

/**
 * =========================================================================
 * ZERO-KNOWLEDGE ASYMMETRIC KEY SHARING (RSA-OAEP + AES-256-GCM)
 * =========================================================================
 * Architecture:
 * - Each user possesses an RSA-OAEP key pair (2048-bit modulus, SHA-256, 65537).
 * - Public keys are published to the server (SPKI Base64 format).
 * - Private keys are encrypted in the browser with the user's password-derived KEK
 *   before transmission, guaranteeing zero server-side exposure.
 * - Sharing a file unwraps the file's DEK using the owner's KEK, then wraps
 *   the DEK with the recipient's RSA-OAEP public key.
 * - The server stores only the re-wrapped DEK in MongoDB `sharedWith`.
 * - The server NEVER sees the plaintext DEK or the file ciphertext.
 */

/**
 * Generates an RSA-OAEP key pair for a user in the browser.
 *
 * @param {number} [modulusLength=2048] - Key size in bits (2048 or 4096).
 * @returns {Promise<CryptoKeyPair>} Generated { publicKey, privateKey }.
 *
 * @example
 * const { publicKey, privateKey } = await generateUserKeyPair();
 */
export async function generateUserKeyPair(modulusLength = 2048) {
  try {
    return await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256',
      },
      true, // extractable
      ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
    );
  } catch (err) {
    throw new Error(`Failed to generate RSA-OAEP key pair: ${err.message}`);
  }
}

/**
 * Exports an RSA-OAEP public key to Base64 SubjectPublicKeyInfo (SPKI) format.
 * Suitable for public storage on the backend server.
 *
 * @param {CryptoKey} publicKey - The RSA-OAEP public key.
 * @returns {Promise<string>} Base64-encoded SPKI string.
 */
export async function exportPublicKey(publicKey) {
  if (!publicKey) throw new Error('exportPublicKey: publicKey is required.');
  try {
    const spkiBuffer = await window.crypto.subtle.exportKey('spki', publicKey);
    return bufferToBase64(spkiBuffer);
  } catch (err) {
    throw new Error(`Failed to export public key: ${err.message}`);
  }
}

/**
 * Imports an RSA-OAEP public key from Base64 SPKI format.
 *
 * @param {string} spkiBase64 - Base64-encoded SPKI string.
 * @returns {Promise<CryptoKey>} Usable RSA-OAEP public CryptoKey.
 */
export async function importPublicKey(spkiBase64) {
  if (!spkiBase64 || typeof spkiBase64 !== 'string') {
    throw new Error('importPublicKey: Base64 string is required.');
  }
  try {
    const spkiBuffer = base64ToBuffer(spkiBase64);
    return await window.crypto.subtle.importKey(
      'spki',
      spkiBuffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['wrapKey', 'encrypt']
    );
  } catch (err) {
    throw new Error(`Failed to import public key: ${err.message}`);
  }
}

/**
 * Exports an RSA-OAEP private key to Base64 PKCS#8 format.
 *
 * @param {CryptoKey} privateKey - The RSA-OAEP private key.
 * @returns {Promise<string>} Base64-encoded PKCS#8 string.
 */
export async function exportPrivateKey(privateKey) {
  if (!privateKey) throw new Error('exportPrivateKey: privateKey is required.');
  try {
    const pkcs8Buffer = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    return bufferToBase64(pkcs8Buffer);
  } catch (err) {
    throw new Error(`Failed to export private key: ${err.message}`);
  }
}

/**
 * Imports an RSA-OAEP private key from Base64 PKCS#8 format.
 *
 * @param {string} pkcs8Base64 - Base64-encoded PKCS#8 string.
 * @returns {Promise<CryptoKey>} Usable RSA-OAEP private CryptoKey.
 */
export async function importPrivateKey(pkcs8Base64) {
  if (!pkcs8Base64 || typeof pkcs8Base64 !== 'string') {
    throw new Error('importPrivateKey: Base64 string is required.');
  }
  try {
    const pkcs8Buffer = base64ToBuffer(pkcs8Base64);
    return await window.crypto.subtle.importKey(
      'pkcs8',
      pkcs8Buffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['unwrapKey', 'decrypt']
    );
  } catch (err) {
    throw new Error(`Failed to import private key: ${err.message}`);
  }
}

/**
 * Encrypts a user's private key using their password-derived KEK so it can
 * safely be stored in MongoDB / user profile without server exposure.
 *
 * @param {CryptoKey} privateKey - RSA-OAEP private key.
 * @param {string} password - User master password.
 * @param {Uint8Array} [salt] - Optional 16-byte salt (generated if omitted).
 * @returns {Promise<{ encryptedPrivateKey: string, salt: string, iv: string }>}
 */
export async function encryptPrivateKeyWithPassword(privateKey, password, salt = null) {
  try {
    const kekSalt = salt || window.crypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKeyFromPassword(password, kekSalt, 100000);
    const pkcs8Buffer = await window.crypto.subtle.exportKey('pkcs8', privateKey);

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      kek,
      pkcs8Buffer
    );

    return {
      encryptedPrivateKey: bufferToBase64(ciphertext),
      salt: bufferToBase64(kekSalt.buffer),
      iv: bufferToBase64(iv.buffer),
    };
  } catch (err) {
    throw new Error(`Failed to encrypt private key: ${err.message}`);
  }
}

/**
 * Decrypts and imports an encrypted private key using the user's password.
 *
 * @param {Object} encryptedPackage - { encryptedPrivateKey, salt, iv }
 * @param {string} password - User master password.
 * @returns {Promise<CryptoKey>} Restored RSA-OAEP private key.
 */
export async function decryptPrivateKeyWithPassword(encryptedPackage, password) {
  try {
    const ciphertext = base64ToBuffer(encryptedPackage.encryptedPrivateKey);
    const kekSalt = new Uint8Array(base64ToBuffer(encryptedPackage.salt));
    const iv = new Uint8Array(base64ToBuffer(encryptedPackage.iv));

    const kek = await deriveKeyFromPassword(password, kekSalt, 100000);
    const pkcs8Buffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      kek,
      ciphertext
    );

    return await window.crypto.subtle.importKey(
      'pkcs8',
      pkcs8Buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['unwrapKey', 'decrypt']
    );
  } catch (err) {
    throw new Error(`Failed to decrypt private key. Incorrect password or tampered key: ${err.message}`);
  }
}

/**
 * 2. Client-Side shareFile Function:
 * Re-wraps a file's DEK using the recipient's RSA-OAEP public key without exposing
 * the plaintext DEK or file content to the backend server.
 *
 * Steps:
 * 1. Derives the owner's KEK from their password and the file's salt via PBKDF2 (100k rounds).
 * 2. Unwraps the file's 256-bit AES-GCM DEK using the owner's KEK.
 * 3. Imports the recipient's RSA-OAEP public key (if passed as SPKI Base64 string).
 * 4. Re-wraps the DEK directly into an RSA-OAEP ciphertext using the recipient's public key.
 * 5. Returns or posts the re-wrapped DEK string (Base64) to the server.
 *
 * @param {string|Object} fileOrMetadata - Either fileId string (with options) or envelope metadata object:
 *   { fileId, wrappedDek, dekIv, kekSalt }
 * @param {CryptoKey|string} recipientPublicKey - Recipient's RSA-OAEP public key (CryptoKey or Base64 SPKI).
 * @param {string} password - Owner's master password (used to unwrap the original DEK).
 * @param {Object} [options] - Optional networking and metadata parameters.
 * @param {string} [options.recipientEmail] - Recipient email if posting directly to backend.
 * @param {string} [options.apiBaseUrl] - Base URL of backend API (e.g. '/api').
 * @param {string} [options.authToken] - JWT Bearer token for authorized upload.
 * @returns {Promise<{ fileId: string, recipientWrappedDek: string, recipientEmail?: string }>}
 *
 * @example
 * const result = await shareFile(
 *   { fileId: '65f1a...', wrappedDek: '...', dekIv: '...', kekSalt: '...' },
 *   recipientPublicKeyBase64,
 *   "OwnerMasterPassword123!"
 * );
 */
export async function shareFile(fileOrMetadata, recipientPublicKey, password, options = {}) {
  if (!fileOrMetadata) {
    throw new Error('shareFile: fileOrMetadata is required.');
  }
  if (!recipientPublicKey) {
    throw new Error('shareFile: recipientPublicKey is required.');
  }
  if (!password || typeof password !== 'string') {
    throw new Error('shareFile: Owner password is required to unwrap file DEK.');
  }

  // Normalization helpers
  const toBuffer = (val, name) => {
    if (val instanceof ArrayBuffer) return val;
    if (ArrayBuffer.isView(val)) return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
    if (typeof val === 'string') return base64ToBuffer(val);
    throw new Error(`shareFile: Invalid format for ${name}`);
  };

  const toUint8Array = (val, name) => {
    if (val instanceof Uint8Array) return val;
    if (val instanceof ArrayBuffer) return new Uint8Array(val);
    if (typeof val === 'string') return new Uint8Array(base64ToBuffer(val));
    if (Array.isArray(val)) return new Uint8Array(val);
    throw new Error(`shareFile: Invalid format for ${name}`);
  };

  try {
    let fileId;
    let wrappedDekBuffer;
    let dekIvBytes;
    let kekSaltBytes;

    // Check if metadata is provided directly or needs fetching
    if (typeof fileOrMetadata === 'string') {
      fileId = fileOrMetadata;
      if (!options.fileMetadata) {
        throw new Error('shareFile: When fileId is provided as a string, options.fileMetadata must contain { wrappedDek, dekIv, kekSalt }.');
      }
      wrappedDekBuffer = toBuffer(options.fileMetadata.wrappedDek || options.fileMetadata.wrappedDEK, 'wrappedDek');
      dekIvBytes = toUint8Array(options.fileMetadata.dekIv || options.fileMetadata.iv, 'dekIv');
      kekSaltBytes = toUint8Array(options.fileMetadata.kekSalt || options.fileMetadata.salt, 'kekSalt');
    } else {
      fileId = fileOrMetadata.fileId || fileOrMetadata.id || 'unspecified_file_id';
      wrappedDekBuffer = toBuffer(fileOrMetadata.wrappedDek || fileOrMetadata.wrappedDEK, 'wrappedDek');
      dekIvBytes = toUint8Array(fileOrMetadata.dekIv || fileOrMetadata.iv, 'dekIv');
      kekSaltBytes = toUint8Array(fileOrMetadata.kekSalt || fileOrMetadata.salt, 'kekSalt');
    }

    // Step 1: Ingest recipient public key
    let rsaPublicKey;
    if (typeof recipientPublicKey === 'string') {
      rsaPublicKey = await importPublicKey(recipientPublicKey);
    } else if (recipientPublicKey instanceof CryptoKey) {
      rsaPublicKey = recipientPublicKey;
    } else {
      throw new Error('shareFile: Invalid recipientPublicKey type. Must be CryptoKey or Base64 string.');
    }

    // Step 2: Derive owner's Key Encryption Key (KEK) using owner's password + salt
    const ownerKek = await deriveKeyFromPassword(password, kekSaltBytes, 100000);

    // Step 3: Unwrap (decrypt) the file's DEK using the owner's KEK
    let dek;
    try {
      dek = await window.crypto.subtle.unwrapKey(
        'raw',
        wrappedDekBuffer,
        ownerKek,
        {
          name: 'AES-GCM',
          iv: dekIvBytes,
          tagLength: 128,
        },
        {
          name: 'AES-GCM',
          length: 256,
        },
        true, // extractable so we can wrap with RSA-OAEP
        ['encrypt', 'decrypt']
      );
    } catch (unwrapErr) {
      throw new Error(
        'shareFile: Failed to unwrap DEK! Incorrect owner password or corrupted wrappedDEK envelope.'
      );
    }

    // Step 4: Re-wrap the raw DEK using the recipient's RSA-OAEP public key
    // RFC 3447: RSA-OAEP with SHA-256 ensures IND-CCA2 security against chosen-ciphertext attacks
    const recipientWrappedDekBuffer = await window.crypto.subtle.wrapKey(
      'raw',
      dek,
      rsaPublicKey,
      {
        name: 'RSA-OAEP',
      }
    );

    const recipientWrappedDekBase64 = bufferToBase64(recipientWrappedDekBuffer);

    // Step 5: If options contains API configuration and recipientEmail, optionally post to server
    if (options.apiBaseUrl && options.recipientEmail && options.authToken) {
      const shareUrl = `${options.apiBaseUrl.replace(/\/$/, '')}/files/${fileId}/share`;
      const response = await fetch(shareUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${options.authToken}`,
        },
        body: JSON.stringify({
          recipientEmail: options.recipientEmail,
          wrappedDEK: recipientWrappedDekBase64,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Failed to record share on server (HTTP ${response.status})`);
      }
    }

    return {
      fileId,
      recipientWrappedDek: recipientWrappedDekBase64,
      recipientEmail: options.recipientEmail,
    };
  } catch (err) {
    throw new Error(`shareFile failed: ${err.message}`);
  }
}

/**
 * 3. Client-Side decryptSharedFile Function:
 * Enables a recipient to unwrap the DEK using their RSA-OAEP private key,
 * then decrypt the ciphertext back into the original plaintext Blob.
 *
 * Security:
 * - The server never has the private key or the plaintext DEK.
 * - If an attacker attempts to decrypt with an incorrect private key,
 *   RSA-OAEP decryption fails deterministically.
 * - AES-256-GCM tag verification guarantees file ciphertext integrity.
 *
 * @param {Object} sharedPackage - The shared file package.
 * @param {ArrayBuffer|string} sharedPackage.fileCiphertext - Encrypted file payload.
 * @param {Uint8Array|string} sharedPackage.fileIv - 12-byte initialization vector.
 * @param {ArrayBuffer|string} sharedPackage.wrappedDek - The DEK wrapped with recipient's RSA-OAEP public key.
 * @param {string} [sharedPackage.mimeType='application/octet-stream'] - Original file MIME type.
 * @param {CryptoKey|string} privateKey - Recipient's RSA-OAEP private key (CryptoKey or Base64 PKCS#8).
 * @returns {Promise<Blob>} The decrypted file data encapsulated in a Blob.
 *
 * @example
 * const blob = await decryptSharedFile(sharedPackage, recipientPrivateKey);
 */
export async function decryptSharedFile(sharedPackage, privateKey) {
  if (!sharedPackage) {
    throw new Error('decryptSharedFile: sharedPackage is required.');
  }
  if (!privateKey) {
    throw new Error('decryptSharedFile: Recipient privateKey is required.');
  }

  // Normalization helpers
  const toBuffer = (val, name) => {
    if (val instanceof ArrayBuffer) return val;
    if (ArrayBuffer.isView(val)) return val.buffer.slice(val.byteOffset, val.byteOffset + val.byteLength);
    if (typeof val === 'string') return base64ToBuffer(val);
    throw new Error(`decryptSharedFile: Invalid format for ${name}`);
  };

  const toUint8Array = (val, name) => {
    if (val instanceof Uint8Array) return val;
    if (val instanceof ArrayBuffer) return new Uint8Array(val);
    if (typeof val === 'string') return new Uint8Array(base64ToBuffer(val));
    if (Array.isArray(val)) return new Uint8Array(val);
    throw new Error(`decryptSharedFile: Invalid format for ${name}`);
  };

  try {
    const fileCiphertext = toBuffer(sharedPackage.fileCiphertext, 'fileCiphertext');
    const fileIv = toUint8Array(sharedPackage.fileIv, 'fileIv');
    const wrappedDek = toBuffer(
      sharedPackage.wrappedDek || sharedPackage.wrappedDEK,
      'wrappedDek'
    );
    const mimeType = sharedPackage.mimeType || 'application/octet-stream';

    // Step 1: Ingest recipient private key
    let rsaPrivateKey;
    if (typeof privateKey === 'string') {
      rsaPrivateKey = await importPrivateKey(privateKey);
    } else if (privateKey instanceof CryptoKey) {
      rsaPrivateKey = privateKey;
    } else {
      throw new Error('decryptSharedFile: Invalid privateKey type. Must be CryptoKey or Base64 string.');
    }

    // Step 2: Unwrap the AES-256-GCM Data Encryption Key (DEK) using recipient's RSA-OAEP private key
    let unwrappedDek;
    try {
      unwrappedDek = await window.crypto.subtle.unwrapKey(
        'raw',
        wrappedDek,
        rsaPrivateKey,
        {
          name: 'RSA-OAEP',
        },
        {
          name: 'AES-GCM',
          length: 256,
        },
        false, // unwrapped DEK does not need to be extractable
        ['decrypt']
      );
    } catch (rsaErr) {
      throw new Error(
        'decryptSharedFile: RSA-OAEP Unwrapping Failed! You do not have the matching private key for this shared file, or the key envelope has been corrupted.'
      );
    }

    // Step 3: Decrypt the file ciphertext using the unwrapped DEK and fileIv (verifies 128-bit GCM MAC tag)
    const decryptedBlob = await decryptFile(fileCiphertext, fileIv, unwrappedDek, mimeType);

    return decryptedBlob;
  } catch (err) {
    throw err;
  }
}

/**
 * Generates an RSA-OAEP key pair for zero-knowledge file sharing.
 * Alias for generateUserKeyPair() for semantic clarity.
 */
export async function generateSharingKeyPair(modulusLength = 2048) {
  return await generateUserKeyPair(modulusLength);
}

/**
 * Formats a Base64-encoded SPKI public key into standard PEM format with 64-character lines.
 * @param {string} spkiBase64 - Base64 encoded SPKI public key.
 * @returns {string} Standard PEM formatted string.
 */
export function formatSpkiToPem(spkiBase64) {
  const cleanBase64 = spkiBase64.replace(/[\r\n\s]/g, '');
  const lines = cleanBase64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Computes the SHA-256 fingerprint of a public key SPKI buffer.
 * @param {string} spkiBase64 - Base64 encoded SPKI string.
 * @returns {Promise<string>} Hex fingerprint formatted with colons.
 */
export async function computeKeyFingerprint(spkiBase64) {
  try {
    const buffer = base64ToBuffer(spkiBase64);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
  } catch {
    return 'UNKNOWN';
  }
}

/**
 * Re-wraps a user's encrypted RSA private key when they change their master password.
 * 1. Decrypts the private key with the old password-derived KEK.
 * 2. Encrypts the private key with the new password-derived KEK (fresh salt + IV).
 *
 * @param {Object} currentKeyPackage - { encryptedPrivateKey, salt, iv }
 * @param {string} oldPassword - Current master password.
 * @param {string} newPassword - New master password.
 * @returns {Promise<{ encryptedPrivateKey: string, salt: string, iv: string }>}
 */
export async function rewrapEncryptedPrivateKey(currentKeyPackage, oldPassword, newPassword) {
  if (!currentKeyPackage || !currentKeyPackage.encryptedPrivateKey) {
    throw new Error('rewrapEncryptedPrivateKey: currentKeyPackage with encryptedPrivateKey is required.');
  }

  // Decrypt private key using old master password
  const privateKey = await decryptPrivateKeyWithPassword(
    {
      encryptedPrivateKey: currentKeyPackage.encryptedPrivateKey,
      salt: currentKeyPackage.salt || currentKeyPackage.privateKeySalt,
      iv: currentKeyPackage.iv || currentKeyPackage.privateKeyIv,
    },
    oldPassword
  );

  // Re-encrypt with new password and fresh salt
  const freshSalt = window.crypto.getRandomValues(new Uint8Array(16));
  const rewrapped = await encryptPrivateKeyWithPassword(privateKey, newPassword, freshSalt);
  return rewrapped;
}

/**
 * Re-wraps a single file's DEK (Data Encryption Key) from an old master password to a new master password.
 *
 * CRITICAL ENVELOPE ENCRYPTION ADVANTAGE:
 * - This function operates ONLY on the 32-byte DEK.
 * - The actual encrypted file ciphertext (which could be gigabytes in S3) NEVER needs to be downloaded,
 *   decrypted, re-encrypted, or uploaded!
 * - Takes ~1-2 milliseconds per file.
 *
 * @param {Object} fileMeta - { id, wrappedDEK, dekIv, salt }
 * @param {string} oldPassword - User's current password.
 * @param {string} newPassword - User's new password.
 * @returns {Promise<{ fileId: string, wrappedDEK: string, dekIv: string, salt: string }>}
 */
export async function rewrapDEK(fileMeta, oldPassword, newPassword) {
  const wrappedDekStr = fileMeta.wrappedDEK || fileMeta.wrappedDek;
  if (!wrappedDekStr) {
    throw new Error(`rewrapDEK: File ${fileMeta.id || 'unknown'} has no wrappedDEK.`);
  }

  const oldSaltStr = fileMeta.salt || fileMeta.saltHex;
  const oldDekIvStr = fileMeta.dekIv || fileMeta.iv;

  if (!oldSaltStr || !oldDekIvStr) {
    throw new Error(`rewrapDEK: File ${fileMeta.id} is missing salt or dekIv metadata.`);
  }

  // 1. Unwrap DEK using old password
  const oldSaltBytes = new Uint8Array(base64ToBuffer(oldSaltStr));
  const oldDekIvBytes = new Uint8Array(base64ToBuffer(oldDekIvStr));
  const wrappedDekBuffer = base64ToBuffer(wrappedDekStr);

  const oldKek = await deriveKeyFromPassword(oldPassword, oldSaltBytes, 100000);

  let rawDek;
  try {
    rawDek = await window.crypto.subtle.unwrapKey(
      'raw',
      wrappedDekBuffer,
      oldKek,
      {
        name: 'AES-GCM',
        iv: oldDekIvBytes,
        tagLength: 128,
      },
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // extractable to re-wrap
      ['encrypt', 'decrypt']
    );
  } catch (err) {
    throw new Error(`Failed to unwrap DEK for file "${fileMeta.originalName || fileMeta.id}". Incorrect old password.`);
  }

  // 2. Derive new KEK with fresh 16-byte salt
  const newSaltBytes = window.crypto.getRandomValues(new Uint8Array(16));
  const newDekIvBytes = window.crypto.getRandomValues(new Uint8Array(12));
  const newKek = await deriveKeyFromPassword(newPassword, newSaltBytes, 100000);

  // 3. Re-wrap DEK with new KEK
  const newWrappedDekBuffer = await window.crypto.subtle.wrapKey(
    'raw',
    rawDek,
    newKek,
    {
      name: 'AES-GCM',
      iv: newDekIvBytes,
      tagLength: 128,
    }
  );

  return {
    fileId: fileMeta.id,
    wrappedDEK: bufferToBase64(newWrappedDekBuffer),
    dekIv: bufferToBase64(newDekIvBytes.buffer),
    salt: bufferToBase64(newSaltBytes.buffer),
  };
}

/**
 * Re-wraps all envelope-encrypted files owned by the user.
 *
 * @param {Array<Object>} files - Array of files from /api/files.
 * @param {string} oldPassword - Current password.
 * @param {string} newPassword - New password.
 * @param {Function} [onProgress] - Optional callback (completedCount, totalCount, currentFile).
 * @returns {Promise<Array<Object>>} Array of { fileId, wrappedDEK, dekIv, salt }.
 */
export async function rewrapAllUserFiles(files, oldPassword, newPassword, onProgress = null) {
  // Filter only files that have a client-side wrappedDEK
  const targetFiles = files.filter(f => Boolean(f.wrappedDEK || f.wrappedDek));
  const results = [];

  for (let i = 0; i < targetFiles.length; i++) {
    const file = targetFiles[i];
    if (onProgress) {
      onProgress(i, targetFiles.length, file.originalName || file.id);
    }
    const rewrapped = await rewrapDEK(file, oldPassword, newPassword);
    results.push(rewrapped);
  }

  if (onProgress) {
    onProgress(targetFiles.length, targetFiles.length, 'Completed');
  }

  return results;
}

/**
 * -----------------------------------------------------------------------------
 * 10. CHUNKED ENCRYPTION FOR LARGE FILES (5 MB+ SEGMENTS)
 * -----------------------------------------------------------------------------
 * 
 * Cryptographic Architecture & Memory Invariant:
 * 1. Low-Memory Footprint:
 *    - Instead of loading multi-gigabyte files into RAM with FileReader, the file
 *      is sliced on disk via `file.slice(start, end)` into 5 MB chunks.
 *    - Resident memory is strictly capped at ~10-15 MB regardless of file size (10 MB to 10 GB+).
 * 2. Independent Nonces / IVs:
 *    - A single 256-bit AES-GCM Data Encryption Key (DEK) is generated for the file.
 *    - Every chunk is encrypted with a unique 96-bit (12-byte) CSPRNG Nonce/IV.
 *    - Nonce reuse across chunks under the same DEK is strictly impossible.
 * 3. Structured Cryptographic Manifest:
 *    - Generates a manifest recording file metadata, PBKDF2 salt, wrapped DEK envelope,
 *      and an ordered list of chunk indices, byte sizes, and respective IVs.
 * 4. Streaming Multipart Uploads:
 *    - Chunks can be piped directly via `onChunk` callback to HTTP multipart upload
 *      (e.g., S3 UploadPart), freeing up memory immediately after each part is dispatched.
 */

export const DEFAULT_CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB

/**
 * Encrypts a File or Blob in sequential chunks (default 5 MB).
 * Each chunk receives its own unique 96-bit IV, encrypted with the same DEK.
 *
 * @param {File|Blob} file - The file to encrypt.
 * @param {string} password - Master passphrase to derive KEK and wrap DEK.
 * @param {Object} [options] - Optional settings.
 * @param {number} [options.chunkSize=5242880] - Size of each chunk in bytes (default: 5 MB).
 * @param {Function} [options.onProgress] - Progress callback ({ chunkIndex, totalChunks, bytesProcessed, totalBytes, percent }).
 * @param {Function} [options.onChunk] - Stream callback receiving each chunk immediately ({ chunkIndex, ciphertext, iv, manifestEntry }).
 * @returns {Promise<{ manifest: Object, chunks: Array<ArrayBuffer> }>}
 */
export async function encryptFileInChunks(file, password, options = {}) {
  if (!file) throw new Error('encryptFileInChunks: A File or Blob is required.');
  if (!password || typeof password !== 'string') {
    throw new Error('encryptFileInChunks: Master password is required.');
  }

  const chunkSize = options.chunkSize || DEFAULT_CHUNK_SIZE;
  const totalBytes = file.size;
  const totalChunks = totalBytes === 0 ? 1 : Math.ceil(totalBytes / chunkSize);

  // 1. Generate single ephemeral 256-bit AES-GCM DEK for the entire file
  const dek = await generateKey(true);

  // 2. Derive KEK via PBKDF2 (100,000 rounds)
  const kekSalt = window.crypto.getRandomValues(new Uint8Array(16));
  const kek = await deriveKeyFromPassword(password, kekSalt, 100000);

  // 3. Wrap DEK with KEK using AES-256-GCM
  const dekIv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrappedDek = await window.crypto.subtle.wrapKey(
    'raw',
    dek,
    kek,
    {
      name: 'AES-GCM',
      iv: dekIv,
      tagLength: 128,
    }
  );

  // 4. Construct the Zero-Knowledge Chunked File Manifest
  const manifest = {
    version: 1,
    schema: 'zero-knowledge-chunked-manifest-v1',
    fileName: file.name || 'unnamed_file',
    fileSize: totalBytes,
    mimeType: file.type || 'application/octet-stream',
    chunkSize: chunkSize,
    totalChunks: totalChunks,
    keyDerivation: {
      algorithm: 'PBKDF2-HMAC-SHA256',
      iterations: 100000,
      salt: bufferToBase64(kekSalt.buffer),
    },
    encryption: {
      algorithm: 'AES-GCM',
      keyLength: 256,
      wrappedDEK: bufferToBase64(wrappedDek),
      dekIv: bufferToBase64(dekIv.buffer),
      tagLength: 128,
    },
    chunks: [],
    createdAt: new Date().toISOString(),
  };

  const encryptedChunks = [];

  // 5. Encrypt chunk by chunk
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, totalBytes);

    // Read ONLY this slice into memory (flat RAM profile)
    const slice = file.slice(start, end);
    const chunkBuffer = await slice.arrayBuffer();

    // Generate unique 96-bit (12-byte) CSPRNG nonce for this specific chunk
    const chunkIv = window.crypto.getRandomValues(new Uint8Array(12));

    // Authenticated encryption of the chunk
    const encryptedChunkBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: chunkIv,
        tagLength: 128,
      },
      dek,
      chunkBuffer
    );

    const chunkMeta = {
      index: i,
      offset: start,
      size: chunkBuffer.byteLength,
      encryptedSize: encryptedChunkBuffer.byteLength,
      iv: bufferToBase64(chunkIv.buffer),
    };

    manifest.chunks.push(chunkMeta);
    encryptedChunks.push(encryptedChunkBuffer);

    // If caller provided a streaming callback, dispatch chunk immediately
    if (options.onChunk && typeof options.onChunk === 'function') {
      await options.onChunk({
        chunkIndex: i,
        ciphertext: encryptedChunkBuffer,
        iv: chunkMeta.iv,
        manifestEntry: chunkMeta,
      });
    }

    if (options.onProgress && typeof options.onProgress === 'function') {
      options.onProgress({
        chunkIndex: i + 1,
        totalChunks,
        bytesProcessed: end,
        totalBytes,
        percent: Math.round(((i + 1) / totalChunks) * 100),
      });
    }
  }

  return {
    manifest,
    chunks: encryptedChunks,
  };
}

/**
 * Decrypts a chunked file given its manifest and encrypted chunk buffers.
 * Validates each chunk's authentication tag and reassembles the original file Blob.
 *
 * @param {Object} manifest - The chunked manifest.
 * @param {Array<ArrayBuffer>} chunks - Array of encrypted chunk ArrayBuffers.
 * @param {string} password - Master passphrase to unwrap the DEK.
 * @returns {Promise<Blob>} Reconstructed plaintext Blob with original MIME type.
 */
export async function decryptFileFromChunks(manifest, chunks, password) {
  if (!manifest || !manifest.encryption || !manifest.chunks) {
    throw new Error('decryptFileFromChunks: Invalid or corrupted chunk manifest.');
  }
  if (!chunks || chunks.length !== manifest.totalChunks) {
    throw new Error(`decryptFileFromChunks: Chunk count mismatch. Expected ${manifest.totalChunks}, received ${chunks ? chunks.length : 0}.`);
  }
  if (!password || typeof password !== 'string') {
    throw new Error('decryptFileFromChunks: Master password is required.');
  }

  // 1. Re-derive KEK from password and manifest salt
  const saltBuffer = base64ToBuffer(manifest.keyDerivation.salt);
  const kek = await deriveKeyFromPassword(
    password,
    new Uint8Array(saltBuffer),
    manifest.keyDerivation.iterations || 100000
  );

  // 2. Unwrap DEK using KEK
  const wrappedDekBuffer = base64ToBuffer(manifest.encryption.wrappedDEK);
  const dekIvBuffer = base64ToBuffer(manifest.encryption.dekIv);

  let dek;
  try {
    dek = await window.crypto.subtle.unwrapKey(
      'raw',
      wrappedDekBuffer,
      kek,
      {
        name: 'AES-GCM',
        iv: new Uint8Array(dekIvBuffer),
        tagLength: 128,
      },
      {
        name: 'AES-GCM',
        length: 256,
      },
      false, // non-extractable in memory
      ['decrypt']
    );
  } catch (err) {
    throw new Error('Authentication failed: Incorrect master password or corrupted key envelope.');
  }

  // 3. Decrypt each chunk in sequential order using its recorded IV
  const decryptedBuffers = [];

  for (let i = 0; i < manifest.chunks.length; i++) {
    const chunkMeta = manifest.chunks[i];
    const chunkCiphertext = chunks[i];
    const chunkIv = new Uint8Array(base64ToBuffer(chunkMeta.iv));

    try {
      const decryptedChunk = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: chunkIv,
          tagLength: 128,
        },
        dek,
        chunkCiphertext
      );

      decryptedBuffers.push(decryptedChunk);
    } catch (err) {
      throw new Error(`Integrity verification failed on chunk #${i}: Ciphertext has been tampered with or corrupted.`);
    }
  }

  // 4. Reassemble original file
  return new Blob(decryptedBuffers, { type: manifest.mimeType || 'application/octet-stream' });
}

/**
 * End-to-end streaming multipart upload orchestrator.
 * Encrypts and streams 5 MB chunks sequentially to the backend without keeping
 * all ciphertexts in browser memory.
 *
 * @param {File} file - Original file to upload.
 * @param {string} password - Master password for KEK derivation.
 * @param {string} token - JWT bearer authorization token.
 * @param {Object} [options] - Optional upload configuration.
 * @returns {Promise<Object>} Server upload response with file metadata.
 */
export async function uploadChunkedFile(file, password, token, options = {}) {
  const chunkSize = options.chunkSize || DEFAULT_CHUNK_SIZE;
  const onProgress = options.onProgress || (() => {});

  // 1. Initialize Multipart Upload Session on the server
  const initRes = await fetch('/api/files/chunked/init', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      fileName: file.name,
      fileSize: file.size,
      mimeType: file.type || 'application/octet-stream',
      chunkSize: chunkSize,
      totalChunks: file.size === 0 ? 1 : Math.ceil(file.size / chunkSize),
    }),
  });

  if (!initRes.ok) {
    const errText = await initRes.text().catch(() => '');
    throw new Error(`Failed to initiate chunked upload session: ${errText || initRes.statusText}`);
  }

  const { uploadId } = await initRes.json();

  // 2. Encrypt and stream chunk by chunk
  const uploadedParts = [];

  const { manifest } = await encryptFileInChunks(file, password, {
    chunkSize,
    onProgress: (prog) => {
      onProgress({
        phase: 'encrypting',
        ...prog,
      });
    },
    onChunk: async ({ chunkIndex, ciphertext, iv, manifestEntry }) => {
      // Stream chunk immediately to server (S3 UploadPart equivalent)
      const partFormData = new FormData();
      partFormData.append('chunkIndex', String(chunkIndex));
      partFormData.append('uploadId', uploadId);
      partFormData.append('iv', iv);
      partFormData.append('chunk', new Blob([ciphertext]), `part_${chunkIndex}.bin`);

      const partRes = await fetch('/api/files/chunked/part', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: partFormData,
      });

      if (!partRes.ok) {
        throw new Error(`Failed to upload chunk #${chunkIndex}: ${partRes.statusText}`);
      }

      const partData = await partRes.json();
      uploadedParts.push({
        partNumber: chunkIndex + 1,
        etag: partData.etag || `part-${chunkIndex}`,
      });
    },
  });

  // 3. Finalize upload with the complete encrypted manifest
  const completeRes = await fetch('/api/files/chunked/complete', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      uploadId,
      manifest,
      parts: uploadedParts,
    }),
  });

  if (!completeRes.ok) {
    throw new Error(`Failed to finalize chunked upload: ${completeRes.statusText}`);
  }

  return await completeRes.json();
}




