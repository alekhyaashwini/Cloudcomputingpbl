# 5-Minute Presentation Script & Examiner Viva Guide
**Project:** Zero-Knowledge Secure Cloud Storage (Client-Side Authenticated Encryption & Asymmetric Sharing)  
**Target Duration:** Exactly 5 Minutes  
**Target Audience:** Academic Examiners, Project Evaluators, Information Security Panel

---

## Part 1: The 5-Minute Live Demonstration Script

### Timeline & Stage Breakdown Overview
| Timecode | Phase | Key Action on Screen | Core Takeaway |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:45** | **1. The Problem & Core Concept** | Landing page / Architecture overview | Explain why SSE fails and how Zero-Knowledge CSE solves it. |
| **0:45 - 1:30** | **2. Registration & Key Derivation** | Register "Alice" + derive keys | PBKDF2 100k rounds; server gets no password or KEK. |
| **1:30 - 2:45** | **3. Upload & Ciphertext Proof (S3 / DB)** | Upload file + open Inspector / S3 view | Prove 0 plaintext bytes, show entropy (7.99 bits/byte), 96-bit IV, 128-bit tag. |
| **2:45 - 3:30** | **4. Zero-Knowledge Decryption & Tamper Lab** | Download file + trigger 1-bit tamper | Decryption happens in browser RAM; tampered ciphertext fails immediately. |
| **3:30 - 4:45** | **5. Multi-User RSA-OAEP Sharing** | Share file with "Bob" + Bob logs in | Asymmetric DEK re-wrapping; server acts as blind coordinator. |
| **4:45 - 5:00** | **6. Conclusion & Impact** | Test Matrix / Results summary | 29/29 automated tests, standards-compliant Web Crypto. |

---

### Step-by-Step Script & Talking Points

#### [0:00 – 0:45] Phase 1: Problem Statement & Architectural Hook
- **On Screen:** Open the application landing screen (`/` Dashboard) showing the Clean Vault UI.
- **Presenter Action:** Stand confident, open browser DevTools (`F12 -> Network tab`) to demonstrate real-time network transparency.
- **Talking Points:**
  > *"Good morning, respected evaluators. In standard cloud storage systems like AWS S3 or Google Drive, data is encrypted using Server-Side Encryption (SSE). While this protects against physical hard drive theft, the cloud provider holds the keys. A rogue employee, a misconfigured IAM role, or a government subpoena exposes all plaintext data.*
  > 
  > *Our project implements a **Zero-Knowledge Cloud Storage System** using **Client-Side Envelope Encryption** via the W3C Web Crypto API. The security invariant of our system is mathematically simple: **the server and the cloud storage never receive, store, or process a single plaintext byte, master password, or unencrypted key.** Everything is encrypted and decrypted exclusively in the client's memory."*

---

#### [0:45 – 1:30] Phase 2: Registration, KEK Derivation & Key Pair Setup
- **On Screen:** Click **"Sign Up"** or **"Register"** modal. Register a new user: `alice@vault.io` with password `Passphrase#2026!`.
- **Presenter Action:** Point to the Network tab during registration.
- **Talking Points:**
  > *"Notice what happens during registration. In the background, the browser executes `window.crypto.subtle` using PBKDF2-HMAC-SHA256 with 100,000 iterations and a cryptographically secure 16-byte random salt.*
  > 
  > *This derives Alice's **Key Encryption Key (KEK)**. Notice in our network payload: the KEK **never leaves the browser**. The server only receives an independent salted hash for authentication. In addition, an asymmetric **RSA-OAEP 2048-bit keypair** is generated for sharing. Alice's public key is registered with the server, while her private key is wrapped with her KEK before transmission."*

---

#### [1:30 – 2:45] Phase 3: File Upload & Proving the Zero-Knowledge Invariant in S3
- **On Screen:** 
  1. Drag and drop a sensitive document (e.g., `Financial_Report_Q4.pdf` or `confidential.txt`).
  2. Click **"Encrypt & Upload"**. Observe the encryption progress bar.
  3. Once uploaded, click the **"Inspect Crypto"** (Magnifying Glass / AEAD Inspector) icon on the file card.
  4. (Optional / Bonus): Switch to the server terminal or AWS S3 console view showing the stored object.
- **Presenter Action:** Point to the **Shannon Entropy** value, the **Nonce/IV**, the **GHASH Tag**, and the raw hex view in the modal.
- **Talking Points:**
  > *"When Alice uploads this file, our client-side engine executes **Envelope Encryption**:*
  > 1. *It generates a fresh, ephemeral 256-bit AES key called the **Data Encryption Key (DEK)**.*
  > 2. *The file is encrypted client-side using **AES-256-GCM** with a unique 96-bit CSPRNG nonce.*
  > 3. *The DEK itself is encrypted using Alice's KEK, creating the `wrappedDEK` envelope.*
  > 
  > *Look at our **Cryptographic Inspector Modal** and the server-side S3 storage dump. What does the cloud hold?*
  > - *Only raw, high-entropy ciphertext.*
  > - *The **Shannon Entropy** measures **7.998 bits per byte**, which is statistically indistinguishable from pure mathematical noise.*
  > - *Even if an adversary dumps the entire S3 bucket and PostgreSQL database right now, they hold zero usable information without Alice's password."*

---

#### [2:45 – 3:30] Phase 4: Authenticated Decryption & The Tamper Lab
- **On Screen:**
  1. Click **"Download & Decrypt"** to verify that the file downloads and opens with 100% byte fidelity.
  2. Navigate to the **"Tamper Lab"** tab in the navigation bar.
  3. Click **"Flip 1 Bit in Cloud Ciphertext"** on the uploaded file.
  4. Attempt to download the file again. Show the red banner: `OperationError: AEAD authentication tag mismatch`.
- **Presenter Action:** Highlight the failed decryption event.
- **Talking Points:**
  > *"Confidentiality is not enough—we must guarantee integrity. We specifically chose **AES-256-GCM** because it is an Authenticated Encryption with Associated Data (AEAD) cipher producing a 128-bit GHASH tag.*
  > 
  > *In our **Tamper Lab**, we simulate an active adversary or rogue storage provider altering just **one single byte** inside the stored S3 ciphertext. When Alice attempts to download the modified file, the Web Crypto engine verifies the authentication tag. Because the tag does not match, the browser instantly rejects the payload and refuses to parse it. This mathematically prevents ciphertext bit-flipping attacks common in older AES-CBC systems."*

---

#### [3:30 – 4:45] Phase 5: Multi-User Sharing via RSA-OAEP Key Encapsulation
- **On Screen:**
  1. Click the **"Share"** button on the file.
  2. Enter recipient email: `bob@vault.io`. Click **"Grant Access"**.
  3. Log out or open an Incognito window. Log in as `bob@vault.io`.
  4. Open the **"Shared With Me"** section. Click **"Download & Decrypt"**. The plaintext file opens seamlessly for Bob!
- **Presenter Action:** Explain the key exchange flow while Bob's file downloads.
- **Talking Points:**
  > *"The hardest challenge in zero-knowledge systems is: **how do you share an encrypted file with another user without revealing your master password or trusting the server?***
  > 
  > *Here is our asymmetric protocol:*
  > 1. *Alice unwraps the file's 256-bit DEK in her browser's volatile memory.*
  > 2. *Her browser fetches Bob's public RSA key from the server.*
  > 3. *Her browser encrypts the DEK using **RSA-OAEP with SHA-256** and sends this new envelope to the server.*
  > 4. *When Bob logs in, his browser downloads the ciphertext and the RSA-wrapped DEK.*
  > 5. *Bob unwraps the DEK using his private RSA key, and decrypts the file.*
  > 
  > *At no point did Alice share her password, did Bob receive Alice's private key, or did the server see the DEK or file plaintext."*

---

#### [4:45 – 5:00] Phase 6: Conclusion & Verification Matrix
- **On Screen:** Navigate to the **"Test Matrix"** view showing the automated test suite summary (29 passing tests across frontend and backend).
- **Presenter Action:** Concluding statement.
- **Talking Points:**
  > *"To validate our implementation, we built a comprehensive test suite with 29 automated tests covering round-trip byte fidelity, nonce uniqueness, PBKDF2 salt isolation, and a verification test confirming the Express server body parser receives strictly ciphertext.*
  > 
  > *This demonstrates that modern browser standards allow us to give users 100% data sovereignty without sacrificing speed or collaboration. Thank you, and I welcome your questions."*

---

## Part 2: 15 Likely Examiner / Viva Questions & Model Answers

### Q1: Why did you choose AES-GCM instead of AES-CBC?
**Model Answer:**  
AES-GCM is an **AEAD (Authenticated Encryption with Associated Data)** mode that simultaneously guarantees confidentiality and cryptographic integrity via a 128-bit GHASH authentication tag. In contrast, AES-CBC provides only confidentiality and requires a separate MAC (Encrypt-then-MAC via HMAC-SHA256) to be secure. Furthermore, AES-CBC is susceptible to padding oracle attacks if padding errors are leaked, whereas AES-GCM fails safely upon any single-bit tampering.

---

### Q2: Where are the encryption keys stored?
**Model Answer:**  
- **Master Password:** Never stored anywhere (neither client disk nor server).
- **Key Encryption Key (KEK):** Exists only ephemerally in browser RAM, derived dynamically upon login via PBKDF2.
- **Data Encryption Key (DEK):** Generated randomly per file; stored on the server **only in wrapped (encrypted) form** inside the file's metadata record.
- **RSA Private Key:** Encrypted with the user's KEK using AES-256-GCM before being stored in the database or client IndexedDB.

---

### Q3: What happens if the server or cloud database is completely compromised?
**Model Answer:**  
The adversary gains access only to ciphertext blobs and encrypted metadata envelopes (`wrappedDEK`, `iv`, `salt`). Because the DEKs are encrypted with client-derived KEKs (100k PBKDF2 iterations) and the server never possesses the master passwords or private keys, the attacker cannot decrypt any stored files. The compromise is confined to metadata leakage (file sizes and timestamps).

---

### Q4: How do you prevent replay attacks?
**Model Answer:**  
At the transport layer, TLS 1.3 uses ephemeral Diffie-Hellman keys (ECDHE) and nonces to prevent packet replay. At the application layer, short-lived signed JWTs with expiration timestamps (`exp`) and unique request nonces are required for all API operations. For file encryption, a unique 96-bit CSPRNG initialization vector (IV) is generated for every single encryption operation, ensuring that identical files produce different ciphertexts.

---

### Q5: Why not use the user's password directly as the AES encryption key?
**Model Answer:**  
1. **Entropy Deficit:** Human passwords typically contain only 30–50 bits of entropy, whereas AES-256 requires 256 bits of uniformly distributed cryptographic entropy.
2. **Key Length:** AES-256 requires a fixed 32-byte key; passwords have arbitrary length.
3. **Vulnerability to Brute-Force:** Using a password directly enables instant dictionary attacks. PBKDF2 expands the password into a 256-bit key while enforcing 100,000 computation cycles to make brute-forcing computationally prohibitive.

---

### Q6: What is envelope encryption, and why didn't you encrypt files directly with the KEK?
**Model Answer:**  
Envelope encryption uses a two-tier key hierarchy: files are encrypted with unique Data Encryption Keys (DEKs), and the DEKs are encrypted with a Key Encryption Key (KEK).  
**Two crucial advantages:**
1. **Password Rotation:** If a user changes their password, we only re-encrypt the small 32-byte DEK envelopes with the new KEK—we do not need to download, decrypt, and re-encrypt gigabytes of file payloads.
2. **Cryptographic Limits:** Reusing the same key to encrypt high volumes of data risks keystream exhaustion and cryptanalytic vulnerabilities under AES-GCM.

---

### Q7: What happens if a user forgets their master password? Can an administrator reset it?
**Model Answer:**  
In a true zero-knowledge system, **an administrator cannot reset the password to restore data access**. Because the KEK is derived mathematically from the password, losing the password destroys the only means of unwrapping the DEKs. To balance security and usability in production, users are issued a deterministic 12- or 24-word recovery phrase (BIP-39 standard) upon registration, which derives a secondary recovery key.

---

### Q8: How does file sharing work if the server cannot read the file or the DEK?
**Model Answer:**  
We use **hybrid public-key cryptography (RSA-OAEP)**:
1. Bob publishes his public RSA key on the server.
2. Alice downloads Bob's public key and unwraps the file's DEK locally in browser memory.
3. Alice encrypts the DEK with Bob's RSA public key and uploads this new envelope to the server's access control table.
4. Bob fetches the envelope, decrypts the DEK using his private RSA key, and decrypts the file.  
The server acts as an untrusted message broker; it never sees the plaintext DEK.

---

### Q9: What is the purpose of the 96-bit IV, and what happens if an IV is reused in AES-GCM?
**Model Answer:**  
The 96-bit Initialization Vector (IV) ensures that encrypting identical plaintext blocks produces completely distinct ciphertexts.  
**Critical Risk:** In AES-GCM, reusing the same $(Key, IV)$ pair is catastrophic: an attacker can XOR the two ciphertexts to cancel out the keystream ($C_1 \oplus C_2 = P_1 \oplus P_2$) and recover the GHASH authentication key $H$, allowing them to forge valid authentication tags for arbitrary messages. We use `crypto.getRandomValues(new Uint8Array(12))` to guarantee unique nonces per encryption.

---

### Q10: How do you handle large files (e.g., 2 GB) without causing browser memory crashes?
**Model Answer:**  
Instead of loading the entire file into an `ArrayBuffer` using `FileReader` (which triggers V8 engine out-of-memory errors), we implement a **chunked streaming pipeline**:
1. The file is partitioned into 4 MB to 8 MB segments using `File.slice()`.
2. Each chunk is encrypted with AES-GCM using a deterministic counter-derived IV ($\text{IV}_i = \text{IV}_{\text{base}} \oplus \text{pad}_{96}(i)$).
3. The chunks are piped via a `ReadableStream` directly into an HTTP multipart upload, maintaining a flat memory footprint ($<35\text{ MB}$ RAM).

---

### Q11: Why did you use PBKDF2 instead of Argon2id or Scrypt?
**Model Answer:**  
Argon2id is memory-hard and theoretically superior against ASIC/GPU attacks. However, **PBKDF2 is natively supported in the W3C Web Cryptography API specification** across all modern browsers without requiring third-party WebAssembly binaries. Argon2 requires compiling C code to Wasm, which introduces external library dependencies, larger bundle sizes, and potential side-channel timing risks. For standard Web Crypto compatibility, PBKDF2 with 100,000 iterations is the NIST/OWASP approved standard.

---

### Q12: Can the server tamper with or inject malicious data into an encrypted file?
**Model Answer:**  
No. If the server or an adversary alters even a single bit of the stored ciphertext, the AES-GCM 128-bit authentication tag verification will fail upon decryption on the client machine (`OperationError`). The client rejects the download immediately and will never execute or render corrupted or injected data.

---

### Q13: How does the application protect against Client-Side Cross-Site Scripting (XSS)?
**Model Answer:**  
If malicious JavaScript executes in the page context, it could read keys from memory. We mitigate this using Defense-in-Depth:
1. **Strict Content Security Policy (CSP):** Disabling `unsafe-eval` and restricting `script-src` to self-hosted origins.
2. **Subresource Integrity (SRI):** Ensuring third-party scripts cannot be tampered with.
3. **Non-Extractable Keys:** Generating Web Crypto `CryptoKey` objects with `extractable: false` where possible, preventing simple `JSON.stringify` exfiltration from the heap.

---

### Q14: What is Shannon Entropy, and why did you measure it on the ciphertext?
**Model Answer:**  
Shannon Entropy measures the degree of randomness and information density in a byte stream, bounded between 0 and 8 bits per byte. Plaintext files have low entropy (typically 1.5–4.5 bits/byte due to repetitive language patterns). High-grade ciphertexts must possess near-maximal entropy ($\approx 7.99\text{ bits/byte}$), proving that the output is statistically indistinguishable from a true random sequence and leaks no statistical patterns to eavesdroppers.

---

### Q15: How does your system compare to AWS S3 Server-Side Encryption (SSE-S3 / SSE-KMS)?
**Model Answer:**  
Under AWS SSE, encryption is performed *by the cloud server* after data has traversed the network, and AWS manages the KMS keys. This protects against stolen physical drives, but leaves data exposed to cloud insider threats, infrastructure compromises, and lawful government seizures. Our system implements **Client-Side Zero-Knowledge Encryption**: keys never leave the client's device, meaning AWS operates purely as a blind storage medium with zero capability to read stored files.
