/**
 * Client-Side Web Cryptography API Service
 * Standard: NIST SP 800-38D (AES-256-GCM) + RFC 8018 (PBKDF2-HMAC-SHA256)
 * 
 * Guarantees:
 * 1. Plaintext files are NEVER transmitted to Express or Amazon S3.
 * 2. Passphrase is NEVER sent to the backend.
 * 3. Even with complete database or cloud storage leaks, attackers cannot decrypt files.
 */

export const bufferToHex = (buffer: ArrayBuffer): string => {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

export const hexToUint8Array = (hexString: string): Uint8Array => {
  const matches = hexString.match(/.{1,2}/g);
  if (!matches) return new Uint8Array(0);
  return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
};

export const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
};

export const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
};

/**
 * Derives a 256-bit AES-GCM key from user passphrase via PBKDF2-HMAC-SHA256 (100,000 rounds)
 */
export async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const rawKeyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 100000,
      hash: 'SHA-256'
    },
    rawKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a File or ArrayBuffer in the browser using AES-256-GCM with a 96-bit random nonce
 */
export async function encryptFileClientSide(
  dataBuffer: ArrayBuffer,
  passphrase: string
): Promise<{
  base64Ciphertext: string;
  ivHex: string;
  authTagHex: string;
  saltHex: string;
  encryptedSize: number;
}> {
  // 1. Generate 16 bytes random salt for PBKDF2
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  
  // 2. Derive 256-bit symmetric AES key
  const cryptoKey = await deriveKey(passphrase, salt);

  // 3. Generate 96-bit (12 bytes) CSPRNG initialization vector (IV)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // 4. Encrypt using AES-GCM (appends 128-bit authentication tag at end of ciphertext)
  const encryptedResult = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128
    },
    cryptoKey,
    dataBuffer
  );

  const payloadArray = new Uint8Array(encryptedResult);
  const tagBytes = payloadArray.slice(payloadArray.length - 16);

  return {
    base64Ciphertext: arrayBufferToBase64(encryptedResult),
    ivHex: bufferToHex(iv.buffer),
    authTagHex: bufferToHex(tagBytes.buffer),
    saltHex: bufferToHex(salt.buffer),
    encryptedSize: encryptedResult.byteLength
  };
}

/**
 * Decrypts a ciphertext ArrayBuffer in the browser using the user's passphrase
 */
export async function decryptFileClientSide(
  base64Ciphertext: string,
  passphrase: string,
  saltHex: string,
  ivHex: string
): Promise<ArrayBuffer> {
  const salt = hexToUint8Array(saltHex);
  const iv = hexToUint8Array(ivHex);
  const ciphertextBuffer = base64ToArrayBuffer(base64Ciphertext);

  const cryptoKey = await deriveKey(passphrase, salt);

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        tagLength: 128
      },
      cryptoKey,
      ciphertextBuffer
    );
    return decrypted;
  } catch (err: any) {
    throw new Error('Integrity Verification Failed: GCM tag mismatch or wrong master passphrase!');
  }
}
