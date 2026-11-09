/**
 * Web Crypto API Service (NIST SP 800-38D)
 * Runs 100% in the user's browser.
 * Plaintext files and secret passphrases NEVER leave the browser!
 */

export interface ClientEncryptedResult {
  ciphertextBuffer: ArrayBuffer;
  ivHex: string;         // 96-bit (12 bytes) IV in hex
  saltHex: string;       // 128-bit (16 bytes) Salt in hex
  authTagHex: string;    // 128-bit (16 bytes) GCM tag in hex
  encryptedSize: number;
}

// Convert ArrayBuffer to Hex string
export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Convert Hex string to Uint8Array
export function hexToUint8Array(hexString: string): Uint8Array {
  const matches = hexString.match(/.{1,2}/g);
  if (!matches) return new Uint8Array(0);
  return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
}

/**
 * Derives a 256-bit AES-GCM CryptoKey from a user passphrase using PBKDF2-HMAC-SHA256
 */
export async function deriveKeyFromPassphrase(
  passphrase: string,
  saltUint8: Uint8Array,
  iterations: number = 100000
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltUint8 as BufferSource,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts an ArrayBuffer of file data using client-side AES-256-GCM.
 * The Web Crypto API automatically calculates and appends the 16-byte (128-bit) tag to the ciphertext.
 */
export async function clientEncryptFile(
  fileBuffer: ArrayBuffer,
  passphrase: string
): Promise<ClientEncryptedResult> {
  // 1. Generate 16 bytes random salt for PBKDF2
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  
  // 2. Derive 256-bit AES-GCM key
  const key = await deriveKeyFromPassphrase(passphrase, salt);

  // 3. Generate 96-bit (12 bytes) CSPRNG nonce
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // 4. Encrypt using Web Crypto API AES-GCM
  // Resulting buffer contains: Ciphertext + 16-byte GCM Authentication Tag
  const encryptedPayload = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      tagLength: 128
    },
    key,
    fileBuffer
  );

  const payloadArray = new Uint8Array(encryptedPayload);
  // Last 16 bytes is the authentication tag
  const tagBytes = payloadArray.slice(payloadArray.length - 16);
  const ciphertextOnly = payloadArray.slice(0, payloadArray.length - 16);

  return {
    ciphertextBuffer: encryptedPayload, // Contains ciphertext + tag as standard WebCrypto format
    ivHex: bufferToHex(iv.buffer),
    saltHex: bufferToHex(salt.buffer),
    authTagHex: bufferToHex(tagBytes.buffer),
    encryptedSize: encryptedPayload.byteLength
  };
}

/**
 * Decrypts ciphertext in the browser using the user's passphrase.
 * Validates the GCM authentication tag.
 * Throws OperationError if ciphertext or tag was tampered with!
 */
export async function clientDecryptFile(
  encryptedPayload: ArrayBuffer,
  passphrase: string,
  saltHex: string,
  ivHex: string
): Promise<ArrayBuffer> {
  const salt = hexToUint8Array(saltHex);
  const iv = hexToUint8Array(ivHex);

  const key = await deriveKeyFromPassphrase(passphrase, salt);

  // Web Crypto API decrypt verifies the 16-byte GCM tag automatically
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        tagLength: 128
      },
      key,
      encryptedPayload
    );
    return decrypted;
  } catch (err: any) {
    throw new Error('CLIENT-SIDE AUTHENTICATION FAILURE: GCM tag mismatch or incorrect passphrase! Ciphertext has been modified or corrupted.');
  }
}
