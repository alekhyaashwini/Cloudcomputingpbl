process.env.NODE_ENV = 'test';
import crypto from 'node:crypto';

// Polyfill window, Web Crypto API, atob, btoa, and Blob for Node.js test environment
if (typeof globalThis.window === 'undefined') {
  globalThis.window = globalThis;
}

if (!globalThis.crypto) {
  // Node 18+ provides crypto.webcrypto
  globalThis.crypto = crypto.webcrypto;
}
if (!globalThis.window.crypto) {
  globalThis.window.crypto = crypto.webcrypto;
}

if (!globalThis.window.btoa) {
  globalThis.window.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
}
if (!globalThis.btoa) {
  globalThis.btoa = globalThis.window.btoa;
}

if (!globalThis.window.atob) {
  globalThis.window.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
}
if (!globalThis.atob) {
  globalThis.atob = globalThis.window.atob;
}
