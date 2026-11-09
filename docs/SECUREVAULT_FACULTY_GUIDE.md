# SECUREVAULT — Faculty Evaluation & Viva Examination Guide
## Secure Cloud File Storage Using Advanced Encryption (NIST SP 800-38D & Zero-Knowledge Architecture)

**Project Team:** D. Pavani Reddy (23R11A62A4), D. Alekhya Ashwini (23R11A62A6), J. Lasya Priya (23R11A62B6)  
**Institution:** Geethanjali College of Engineering and Technology (CSE – Cyber Security)  
**Academic Year:** 2026–2027 (B.Tech Final-Year / PBL)

---

## 1. EXECUTIVE SYSTEM SUMMARY

**SECUREVAULT** is an advanced, production-grade cloud security web application engineered to guarantee **Zero-Knowledge confidentiality, cryptographic integrity, and controlled multi-tenant sharing**.

Traditional cloud storage systems (such as standard Google Drive or AWS S3 buckets) rely on *Server-Side Encryption*, where the server receives plaintext files and holds decryption keys. If the cloud server, database, or admin credentials are compromised, all stored files are exposed in plaintext.

SECUREVAULT eliminates this vulnerability through **Client-Side Zero-Knowledge Cryptography**:
1. **Client-Side Web Crypto API (`window.crypto.subtle`):** Files are encrypted **inside the user's browser memory** using **AES-256-GCM** before network transmission.
2. **Envelope Encryption:** Each file is sealed with an independent 256-bit Data Encryption Key (DEK). The DEK is wrapped using a Key Encryption Key (KEK) derived via **PBKDF2-HMAC-SHA256 (100,000 rounds)** from the user's master secret.
3. **Zero Plaintext at Rest:** The cloud server and database receive **only ciphertext buffers (`.enc`)**, wrapped key envelopes, 96-bit CSPRNG initialization vectors (IVs), and 128-bit GHASH authentication tags.
4. **Asymmetric Zero-Knowledge Sharing (RSA-OAEP):** When sharing with another user, the DEK is re-wrapped using the recipient's public key. The recipient recovers the DEK using their private key. The server never observes plaintext or master keys.
5. **Interactive Tamper Lab:** A built-in security lab allowing evaluators to flip bits in stored ciphertext to observe real-time cryptographic authentication rejection.

---

## 2. THE 4 KILLER FACULTY DEMONSTRATIONS

When presenting to your faculty guide or external evaluator, execute these 4 demonstrations in order:

### Demonstration 1: True Zero-Knowledge Confidentiality
* **Action:**
  1. Open the application at **`http://localhost:3000`**.
  2. In the **Envelope Vault** tab, upload a sample file (e.g. `confidential_rubric.pdf`).
  3. Notice the live status badge: **"AES-256-GCM (AEAD) — 256-bit Key, 96-bit IV, 128-bit Auth Tag"**.
  4. Open the **Crypto Inspector** modal (Eye icon).
  5. Show the evaluator the storage directory `vault_data/`: the file is stored as pure, high-entropy binary ciphertext.
* **Viva Explanation:**
  > *"Respected faculty, notice that the file was encrypted inside the browser using the W3C Web Cryptography API before any byte left our machine. Neither the network sniffer nor the backend storage administrator can read a single character of this document."*

---

### Demonstration 2: Cryptographic Tamper Detection (The Tamper Lab)
* **Action:**
  1. Click on the **Tamper Lab** tab in the top navigation bar.
  2. Select `confidential_rubric.pdf` from the dropdown list.
  3. Click **"Simulate 1-Bit Ciphertext Flip (Adversary Tampering)"**.
  4. The system flips a single byte in the ciphertext payload in storage.
  5. Click **"Attempt Authenticated Decryption"**.
  6. **Result:** An immediate **CRITICAL SECURITY ALERT** banner is triggered:
     > *"SECURITY ALERT: Cryptographic Authentication Tag Mismatch! The ciphertext has been corrupted or tampered with. Decryption rejected."*
  7. Exactly zero bytes of corrupted plaintext are released.
* **Viva Explanation:**
  > *"Traditional AES-CBC or AES-CTR modes only provide confidentiality. If an adversary flips bits in CBC mode, it produces garbage or padding oracle exploits. In our system, AES-256-GCM computes a 128-bit GHASH polynomial MAC tag over the ciphertext. If even a single bit in storage is modified, the tag check fails mathematically, aborting decryption instantly."*

---

### Demonstration 3: Multi-User Zero-Knowledge Sharing (RSA-OAEP Key Re-Wrapping)
* **Action:**
  1. Upload a file as user **Alice**.
  2. Click **Share** on Alice's file, and enter recipient **`bob`**.
  3. Log in as **Bob** (`student@college.edu`).
  4. Bob can see Alice's shared file, click **Decrypt & Download**, and successfully recover the original PDF!
  5. Now log in as **Eve** (unauthorized third-party).
  6. Show that Eve's vault has zero access, and direct API requests to download return **`403 Forbidden`**.
* **Viva Explanation:**
  > *"In traditional sharing, servers share raw decryption keys. In SECUREVAULT, Alice's browser retrieves Bob's RSA-OAEP public key, re-wraps the file's DEK with Bob's public key, and stores the re-wrapped envelope. Bob uses his client-side private key to decrypt the DEK. The server remains a blind zero-knowledge storage relay."*

---

### Demonstration 4: Automated Test Suite (32/32 Passing)
* **Action:**
  1. In the navigation bar, click the **Test Matrix** tab.
  2. Or in PowerShell, run: `npm run test:frontend` and `npm run test:backend`.
  3. Show the faculty all **32 automated Jest unit and integration tests passing**!

---

## 3. COMPREHENSIVE VIVA VOCE QUESTIONS & MODEL ANSWERS

#### Q1: What is the fundamental difference between Server-Side Encryption (SSE) and Zero-Knowledge Client-Side Encryption?
**Answer:**
- In **Server-Side Encryption** (e.g. AWS SSE-S3), plaintext is transmitted to the cloud server, which encrypts it before writing to disk. The cloud provider has full access to both the plaintext in memory and the decryption keys.
- In **Zero-Knowledge Client-Side Encryption**, encryption occurs strictly inside the client's browser (via `window.crypto.subtle`) before network transmission. The cloud server receives only ciphertext (`.enc`), wrapped keys, and nonces. The server has zero knowledge of plaintext or master secrets.

#### Q2: Why is AES-256-GCM classified as an AEAD cipher?
**Answer:**
AEAD stands for **Authenticated Encryption with Associated Data** (NIST SP 800-38D). It simultaneously guarantees:
1. **Confidentiality:** Through CTR (Counter) mode encryption with 256-bit symmetric keys.
2. **Authenticity & Integrity:** Through a 128-bit authentication tag generated via the GHASH polynomial function over Galois Field $\text{GF}(2^{128})$. It eliminates the need for separate HMAC hashing.

#### Q3: What is the purpose of the 96-bit Nonce / IV in AES-GCM and what happens if it is reused?
**Answer:**
The Nonce (Number used Once) ensures that identical plaintexts produce completely distinct ciphertexts. NIST SP 800-38D mandates a 96-bit (12-byte) length for optimal performance and security. If a nonce is ever reused with the same key, an adversary can XOR the ciphertexts to eliminate the keystream and compute the authentication hash key $H$ (known as the **GCM Forbidden Attack**), permanently destroying both confidentiality and authenticity. SECUREVAULT generates a fresh CSPRNG nonce (`crypto.getRandomValues`) for every single encryption.

#### Q4: How does Envelope Encryption work in your project?
**Answer:**
1. A fresh 256-bit **Data Encryption Key (DEK)** is generated per file.
2. The file is encrypted using the DEK via AES-256-GCM.
3. The DEK itself is encrypted (wrapped) with a **Key Encryption Key (KEK)** derived from the user's password using **PBKDF2-HMAC-SHA256 (100,000 iterations)**.
4. Only the wrapped DEK is stored alongside the ciphertext.
5. This architecture enables fast key rotation: rotating a master password only requires re-wrapping the small 32-byte DEK, rather than re-encrypting multi-gigabyte files.

#### Q5: How is Large-File Chunked Encryption handled?
**Answer:**
For files exceeding standard buffer limits, the file is segmented into 5MB chunks. Each chunk receives its own independent 96-bit nonce and 128-bit authentication tag. A cryptographic manifest binds chunk sequence numbers and hashes to prevent chunk deletion, reordering, or truncation attacks.

---

## 4. PROJECT ARCHITECTURE & FILE MAPPING

| Module | Source Location | Cryptographic Function |
| :--- | :--- | :--- |
| **Client WebCrypto Engine** | `src/services/webCrypto.ts` | In-browser AES-256-GCM, PBKDF2 (100k rounds) |
| **Envelope & Sharing Engine**| `src/services/encryption.js` | DEK wrapping, RSA-OAEP asymmetric key exchange |
| **Interactive Vault View** | `src/components/FileStorage.jsx` | Zero-knowledge upload, download, and key caching |
| **Tamper Simulation Lab** | `src/components/TamperLabView.tsx` | Live ciphertext bit-flipping & tag verification |
| **Crypto Inspector** | `src/components/CryptoInspectorModal.tsx`| Inspection of IVs, GHASH tags, SHA-256 fingerprints |
| **Cloud Storage Backend** | `server.ts` & `src/server/storageAndCrypto.ts` | Local filesystem storage + AWS S3 adapter |
| **Frontend Test Suite** | `tests/frontend/encryption.test.js` | 16 automated Jest WebCrypto unit tests |
| **Backend Integration Suite**| `tests/backend/api.test.js` | 16 automated Supertest REST API tests |
| **Python Vault Backend** | `secure-cloud-storage/` | 20 Pytest unit tests for Python/Flask backend |
