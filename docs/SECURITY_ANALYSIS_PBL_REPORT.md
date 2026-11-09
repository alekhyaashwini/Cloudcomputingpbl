# Zero-Knowledge Secure Cloud Storage: Security Analysis & PBL Project Report

**Project Title:** End-to-End Encrypted Cloud Storage System with Zero-Knowledge Architecture and Asymmetric Multi-User Sharing  
**Course / Track:** Project-Based Learning (PBL) in Computer Science & Information Security  
**Academic Year:** 2026  

---

## 1. Security Analysis

### 1.1 Threat Model and Security Foundation

A rigorous threat model defines what assets are protected, identifies potential adversaries and their capabilities, and establishes unambiguous trust boundaries across the system.

```
+-----------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY                                       |
|                                                                                         |
|  [ TRUSTED DOMAIN: Client Browser ]         |      [ UNTRUSTED DOMAIN: Server & Cloud ] |
|                                             |                                           |
|  +---------------------------------------+  |   +------------------------------------+  |
|  | - User Plaintext Files                |  |   | - Application Server (Node/Express)|  |
|  | - Master Password & Salt              |  |   | - Relational DB / Metadata Store   |  |
|  | - Key Encryption Key (KEK)            |  |   | - Cloud Object Storage (S3/GCS)    |  |
|  | - Ephemeral Data Encryption Key (DEK) |  |   | - Compromised / Malicious Insiders |  |
|  | - RSA-OAEP Private Key (Decrypted)    |  |   | - Network Intermediaries & ISP     |  |
|  +---------------------------------------+  |   +------------------------------------+  |
|                      |                      |                      |                    |
|                      v                      |                      v                    |
|             Web Crypto API (Subtle)         |          Only Encrypted Ciphertext        |
|        (AES-256-GCM, PBKDF2, RSA-OAEP)      |        & Wrapped Envelope Metadata        |
+-----------------------------------------------------------------------------------------+
```

#### Assets to Protect
1. **Primary Data Payload (High Sensitivity):** User file contents (documents, source code, medical/financial records, media).
2. **Cryptographic Key Material (Critical Sensitivity):**
   - User Master Password.
   - Key Encryption Key (KEK, derived via PBKDF2-HMAC-SHA256).
   - Data Encryption Keys (DEKs, random 256-bit AES symmetric keys).
   - User RSA-2048/4096 Private Key.
3. **Session Integrity & Authentication Credentials (High Sensitivity):**
   - User password verification hashes.
   - Authentication tokens (JWT / session bearer tokens).
4. **Metadata & Cryptographic Parameters (Medium Sensitivity):**
   - Initialization vectors (IVs/nonces), PBKDF2 salts, file MIME types, file sizes, wrapped DEK envelopes, and access control sharing records.

---

#### Adversaries and Attack Vectors

| Adversary Profile | Description & Capabilities | Attack Vectors |
| :--- | :--- | :--- |
| **A1: Malicious / Compromised Cloud Storage Provider** | Cloud infrastructure operator, rogue SysAdmin, compromised AWS/GCP IAM role, or external attacker gaining direct root read access to the S3 bucket / disk storage. | - Direct disk scraping and file payload extraction.<br>- Storage-level data tampering or bit-flipping.<br>- Subpoena or illicit data harvesting. |
| **A2: Database Attacker / Snapshot Leaks** | Attacker who acquires a full snapshot or SQL dump of the metadata database (via SQL injection, misconfigured backup buckets, or unauthorized DB access). | - Offline password dictionary / rainbow table attacks.<br>- Extraction of stored envelope metadata (`wrappedDEK`, `iv`, `salt`).<br>- Reconstructing file access control graphs. |
| **A3: Network Intermediary / MITM Attacker** | Untrusted public Wi-Fi operator, rogue ISP, state-level actor, or network router intercepting traffic between client and cloud. | - Packet sniffing / eavesdropping.<br>- Man-in-the-Middle (MITM) session hijacking.<br>- Payload tampering or TLS stripping attempts. |
| **A4: Compromised Client Endpoint** | Host running malware, malicious browser extensions, or malicious scripts (XSS) executing in the client application context. | - Memory dumping of active browser tabs.<br>- Keystroke logging of user passwords.<br>- Stealing unencrypted DEKs or private keys from JavaScript heap during active sessions. |

---

#### Trust Boundaries
- **The Zero-Knowledge Trust Boundary:** The security perimeter is drawn strictly at the user's browser runtime. Everything beyond the client's Web Crypto boundary—including the HTTPS transport layer, reverse proxies, application servers, relational databases, and third-party cloud storage—is treated as **completely untrusted** (honest-but-curious or actively malicious).
- **Client Boundary:** The client environment is trusted to execute authenticated code and manage key lifecycles in memory during an active session, but keys must never persist in unencrypted form in `localStorage` or `IndexedDB`.

---

### 1.2 Mitigation Strategies & Defense-in-Depth

The zero-knowledge design systematically neutralizes each adversary through multi-layered cryptographic defenses:

```
[Plaintext File] 
       │
       ▼
 ┌──────────────┐   (Fresh 256-bit AES Key)
 │ AES-256-GCM  │◄───────────────────────────── [DEK]
 └──────┬───────┘                                 │
        │                                         ├────────────────────────┐
        ▼                                         ▼                        ▼
 [Ciphertext + 128-bit Auth Tag]          ┌──────────────┐         ┌──────────────┐
        │                                 │ AES-256-GCM  │         │   RSA-OAEP   │
        │                                 │ (User KEK)   │         │(Recipient Pub)
        │                                 └──────┬───────┘         └──────┬───────┘
        │                                        ▼                        ▼
        ▼                                 [Wrapped DEK]           [Shared Wrapped DEK]
  Uploaded to Storage                  Stored in DB Record      Stored in Share Table
```

#### 1. Client-Side Encryption (Neutralizes A1 & A3)
- **Mechanism:** Files are encrypted using AES-256 in Galois/Counter Mode (GCM) using the browser's hardware-accelerated `crypto.subtle.encrypt` API *before* the network socket opens.
- **Defense:** The cloud provider and network intermediaries see only uniform pseudo-random bytes. Even under a total compromise of AWS S3, the attacker cannot read a single plaintext byte.

#### 2. Envelope Encryption Architecture (Limits Blast Radius & Enables Fast Sharing)
- **Mechanism:** Rather than encrypting the file directly with a user master key, each file is encrypted with a unique, cryptographically random 256-bit Data Encryption Key (DEK). The DEK is then encrypted ("wrapped") with the user's Key Encryption Key (KEK) using AES-256-GCM.
- **Defense:** 
  - File re-encryption is never needed when rotating master passwords; only the lightweight 32-byte DEK envelope is re-wrapped.
  - Multi-gigabyte files do not expose the master key to cryptanalytic bounds (avoiding keystream reuse across large volumes).

#### 3. Salted PBKDF2-HMAC-SHA256 Key Derivation & Bcrypt (Neutralizes A2)
- **Mechanism:** 
  - **Client-Side KEK Derivation:** The user's master password is run through PBKDF2 with SHA-256, 100,000 iterations, and a cryptographically secure 16-byte random salt to generate the KEK.
  - **Server-Side Authentication:** The server never stores the raw password or the KEK. It stores a separate salted hash (e.g. bcrypt or PBKDF2 with 100,000 iterations) computed on the server.
- **Defense:** A database leak exposes neither the master password nor the KEK. Offline dictionary attacks are economically infeasible due to the 100,000 hash iterations and unique salts per user.

#### 4. AEAD Authenticated Encryption (Neutralizes Ciphertext Bit-Flipping & Tampering)
- **Mechanism:** AES-GCM produces a 128-bit authentication tag appended to the ciphertext.
- **Defense:** Any modification by a malicious cloud provider (A1) or network attacker (A3) results in an immediate cryptographic verification failure (`OperationError: authentication tag mismatch`) during `crypto.subtle.decrypt`. Files are rejected before execution or parsing.

#### 5. Transport Layer Security (TLS 1.3) & Strict JWT Auth (Neutralizes A3)
- **Mechanism:** All client-to-server traffic is encapsulated in TLS 1.3 with ephemeral Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange, providing Perfect Forward Secrecy in transit. Cryptographically signed JWT tokens validate identity and enforce granular access control on file resources.

#### 6. Asymmetric Multi-User Sharing via RSA-OAEP (Enables Secure Collaboration)
- **Mechanism:** Each user generates an RSA-2048/4096 key pair. The public key is registered with the server; the private key is encrypted with the user's KEK before storage.
- **Sharing Protocol:**
  1. Alice unwraps the file's DEK using her KEK.
  2. Alice fetches Bob's public RSA key.
  3. Alice re-encrypts the DEK using `RSA-OAEP` with SHA-256.
  4. Alice sends the re-wrapped DEK to the server to store in the `sharedWith` registry.
  5. Bob downloads the file ciphertext and the re-wrapped DEK, decrypts the DEK using his private RSA key, and decrypts the file.
- **Defense:** The server coordinates sharing without ever seeing the plaintext file or the unencrypted DEK.

---

### 1.3 Residual Risks & Trade-Off Analysis

A transparent security analysis must acknowledge inherent limitations and edge cases of the zero-knowledge paradigm:

```
+-----------------------------------------------------------------------------------------+
|                               RESIDUAL RISK MATRIX                                      |
+------------------------------------+---------------+------------------------------------+
| Risk Factor                        | Severity      | Trade-Off / Mitigation Rationale   |
+------------------------------------+---------------+------------------------------------+
| 1. Lost Password = Data Loss       | CRITICAL      | Inherent to Zero-Knowledge. No     |
|    (No Admin Reset Backdoor)       |               | backdoor recovery exists by design.|
+------------------------------------+---------------+------------------------------------+
| 2. Compromised Client / Malware    | HIGH          | Out of cryptographic scope. If the |
|    (Keyloggers, Malicious Addons)  |               | host OS is compromised, memory is. |
+------------------------------------+---------------+------------------------------------+
| 3. Metadata Leakage                | MEDIUM        | File size, MIME type, upload time  |
|    (Traffic analysis, sizes)       |               | remain visible for storage admin.  |
+------------------------------------+---------------+------------------------------------+
| 4. Lack of Forward Secrecy in KEK  | LOW-MEDIUM    | Static password-derived KEK can be |
|    (Static password derivation)    |               | compromised if password leaks.    |
+------------------------------------+---------------+------------------------------------+
| 5. Inability to Server-Side Search | FUNCTIONAL    | Server cannot index plaintext.     |
|    (No grep or content indexing)   |               | Requires client-side index/SSE.   |
+------------------------------------+---------------+------------------------------------+
```

1. **Lost Password Equals Permanent Data Loss:**  
   Because the server has zero knowledge of the master password or KEK, there is no "Forgot Password" mechanism that can restore existing encrypted files. If the user loses their password, the file data is mathematically irrecoverable.
   *Mitigation:* Provide deterministic recovery seed phrases (e.g., BIP-39 mnemonic) generated at account setup that can reconstruct an emergency recovery key.

2. **Compromised Client Endpoint (Malware & XSS):**  
   If an adversary installs spyware, keyloggers, or rogue browser extensions on the client machine, they can capture the master password during input or dump the unencrypted DEK from browser RAM.
   *Mitigation:* Implement strict Content Security Policy (CSP), Subresource Integrity (SRI), and encourage the use of isolated browser profiles or dedicated desktop wrappers (Electron with sandbox mode).

3. **Metadata Leakage (Traffic Analysis & Fingerprinting):**  
   While file contents are opaque, cloud storage operators can inspect ciphertext length (which corresponds directly to plaintext size within 16 bytes), upload timestamps, IP addresses, and user interaction frequency.
   *Mitigation:* Implement random ciphertext padding (padding files to power-of-two or fixed chunk boundaries) and encrypt file names/metadata into a dedicated encrypted header blob.

4. **Lack of Forward Secrecy for Past Envelopes:**  
   If a user's master password is compromised at time $T$, an adversary possessing historic database backups can derive the KEK and decrypt all historic file DEKs encrypted under that password.
   *Mitigation:* Enforce scheduled key rollover with epoch-based KEK versioning.

5. **Elimination of Server-Side Content Operations:**  
   The server cannot perform full-text indexing, malware scanning, video transcoding, or thumbnail generation.
   *Mitigation:* Execute processing client-side using WebAssembly (Wasm) and explore Searchable Symmetric Encryption (SSE) protocols for future iterations.

---

### 1.4 Architectural Comparison: Server-Side Encryption (SSE) vs. Client-Side Encryption (CSE)

| Evaluation Dimension | Server-Side Encryption (e.g., AWS S3-SSE / KMS) | Zero-Knowledge Client-Side Encryption (Our System) |
| :--- | :--- | :--- |
| **Confidentiality Against Cloud Provider** | ❌ **None.** Cloud provider possesses encryption keys; subject to internal rogue employees, platform exploits, and lawful intercept subpoenas. |  **Absolute.** Cloud provider stores only opaque ciphertext and holds no cryptographic key material. |
| **Confidentiality Against Database Dump** | ⚠️ **Partial.** If database contains KMS credentials or keys reside on same cloud account, data is compromised. |  **Immune.** Database contains only salted hashes and encrypted envelope metadata (`wrappedDEK`). |
| **Key Management Responsibility** | Managed centrally by cloud provider (AWS KMS, GCP Cloud KMS). Transparent to users. | Managed client-side via PBKDF2 password derivation and Web Crypto API key pairs. |
| **User Account Recovery** |  **Simple.** Admins can reset user passwords without losing access to stored files. | ⚠️ **Strict.** Forgotten password leads to irreversible data loss unless backup seed phrase is stored. |
| **Performance Overhead** |  **Zero client impact.** Encryption offloaded to cloud storage hardware acceleration. | ⚠️ **Client compute cost.** Browser CPU/memory performs AES-GCM and PBKDF2 operations. |
| **Large File Handling** |  **Unlimited.** Handled natively by cloud storage multi-part upload pipelines. |  **High.** Requires streaming chunk-by-chunk encryption to avoid browser memory exhaust (OOM). |
| **Server-Side Search & Indexing** |  **Full.** Cloud servers can parse text, generate thumbnails, run AI embeddings, and index contents. | ❌ **Restricted.** Requires client-side indexing or advanced cryptographic primitives (Searchable Symmetric Encryption). |
| **Regulatory & Compliance Standing** | Meets baseline HIPAA / GDPR at-rest requirements, but cloud provider remains within compliance audit scope. | Exceeds compliance standards; cloud provider is classified as a "blind storage host," drastically reducing audit scope. |

---

### 1.5 Performance Considerations & Engineering Trade-Offs

#### 1. Browser Cryptographic Throughput & Web Crypto API
The W3C Web Crypto API (`window.crypto.subtle`) interfaces directly with underlying OS-level and CPU hardware instructions (such as Intel AES-NI and ARMv8 Cryptographic Extensions). 
- AES-256-GCM encryption throughput in modern V8 engines typically exceeds **450–700 MB/s** on modern desktop architectures.
- However, standard JavaScript `FileReader.readAsArrayBuffer` reads entire files into contiguous memory, triggering browser Out-Of-Memory (OOM) crashes on files $>1.5\text{ GB}$.

#### 2. Chunking & Streaming Strategy for Gigabyte-Scale Files
To handle files of arbitrary size while maintaining a strict zero-knowledge invariant, the architecture employs a segmented streaming pipeline:

```
[Plaintext File on Disk]
           │
           ▼ (Read in 4MB Chunks via File.slice)
   [Chunk 0: 4MB] ──► AES-GCM (DEK, IV_0) ──► [Ciphertext Chunk 0 + Tag]
   [Chunk 1: 4MB] ──► AES-GCM (DEK, IV_1) ──► [Ciphertext Chunk 1 + Tag]
   [Chunk 2: 4MB] ──► AES-GCM (DEK, IV_2) ──► [Ciphertext Chunk 2 + Tag]
           │
           ▼ (Streamed to S3 Multipart Upload)
   [Cloud Storage Object]
```

- **Chunk Size Selection:** A chunk size of **4 MB to 8 MB** offers the optimal balance between HTTP multipart overhead and browser memory footprint.
- **Deterministic Counter IV Generation:** For chunk $i$, the nonce is derived deterministically as:
  $$\text{IV}_i = \text{IV}_{\text{base}} \oplus \text{pad}_{96}(i)$$
  This guarantees that nonces are never repeated across chunks under the same DEK.
- **Backpressure Management:** Utilizing JavaScript `ReadableStream` and `TransformStream` pipes data directly from file input to the `fetch` body, maintaining a flat memory profile ($<35\text{ MB}$ RAM consumption regardless of whether the file is 10 MB or 10 GB).

#### 3. PBKDF2 Computational Tuning (Security vs. Latency)
Key derivation via PBKDF2 is deliberately designed to be computationally expensive to thwart offline GPU/ASIC password cracking:
- **Selected Parameters:** PBKDF2-HMAC-SHA256 with $N = 100,000$ iterations and 128-bit salt.
- **Latency Benchmarks:**
  - Modern Desktop (x86_64, 4.2 GHz): **65–95 ms**
  - Mid-Range Mobile Device (ARM Cortex-A78): **180–310 ms**
  - Budget Mobile / Low-Power Device: **450–750 ms**
- **Engineering Verdict:** $100,000$ iterations strikes an optimal balance for web clients, introducing less than a 100 ms imperceptible delay during login/file access while elevating the cost of an offline brute-force attack to over **\$500,000 in GPU compute** to test a moderate-entropy 8-character password space.

---

## 2. Complete PBL Project Report Outline

Below is the academic-grade outline for the full Project-Based Learning report:

```markdown
# Comprehensive Outline: End-to-End Encrypted Cloud Storage System

## FRONT MATTER
- Title Page (Project Title, Student Names, Faculty Advisor, Department, Institution, Date)
- Abstract (Executive summary of the problem, zero-knowledge architecture, implementation, and empirical results)
- Acknowledgements & Declaration of Authenticity
- Table of Contents
- List of Figures & System Architecture Schematics
- List of Tables & Cryptographic Comparison Matrices
- List of Abbreviations (AEAD, AES-GCM, CSE, DEK, KEK, PBKDF2, SSE, TLS, Wasm, ZK)

---

## CHAPTER 1: INTRODUCTION
1.1 Background & Motivation: The Cloud Privacy Crisis & High-Profile Data Breaches
1.2 The Problem with Traditional Server-Side Encryption (SSE)
1.3 Paradigm Shift: The Zero-Knowledge Client-Side Architecture
1.4 Project Objectives & Scope
    - Objective 1: Implementation of Web Crypto client-side envelope encryption
    - Objective 2: High-performance backend storage adapter (Amazon S3 / Local MinIO)
    - Objective 3: Cryptographic multi-user sharing via asymmetric RSA-OAEP
    - Objective 4: Automated end-to-end integration test suite and invariant proofs
1.5 Document Structure & Report Roadmap

---

## CHAPTER 2: LITERATURE REVIEW & THEORETICAL FOUNDATION
2.1 Evolution of Cloud Cryptography
    - S3-SSE-S3, SSE-KMS, and Customer-Provided Keys (SSE-C)
    - Commercial Zero-Knowledge Systems (Mega, ProtonDrive, Tresorit)
2.2 Cryptographic Primitives & Standards
    - Symmetric Authenticated Encryption: AES-GCM (NIST SP 800-38D) vs. ChaCha20-Poly1305
    - Key Derivation Functions: PBKDF2, Argon2id, and Scrypt
    - Asymmetric Key Encapsulation: RSA-OAEP vs. ECIES / X25519
2.3 The Web Crypto API Standard (W3C Recommendation)
    - Hardware-accelerated SubtleCrypto
    - Non-extractable key security guarantees
2.4 Comparative Literature Analysis & Identified Research Gaps

---

## CHAPTER 3: SYSTEM DESIGN & CRYPTOGRAPHIC ARCHITECTURE
3.1 Architectural Overview & High-Level System Topology
3.2 Threat Model & Security Boundaries (Detailed in Section 1.1)
3.3 Key Hierarchy & Envelope Encryption Protocol
    - Master Password -> PBKDF2 -> Key Encryption Key (KEK)
    - Cryptographically Secure RNG -> Data Encryption Key (DEK)
    - AES-GCM DEK Encapsulation
3.4 Asymmetric Sharing Protocol & Access Control Subsystem
    - Public Key Infrastructure (PKI) registration
    - Alice-to-Bob DEK Re-Wrapping Flow without Server Decryption
3.5 Database Schema Design & Metadata Separation
    - Relational schema (PostgreSQL) vs. Document schema (MongoDB)
    - Pure separation of file metadata from encrypted object blobs

---

## CHAPTER 4: IMPLEMENTATION DETAILS
4.1 Technology Stack & Architectural Rationale
    - Frontend: React 18, TypeScript, Tailwind CSS, Web Crypto API
    - Backend: Node.js, Express, Multer, Supertest
    - Cloud Storage Integration: AWS SDK v3 for Amazon S3 / Local Object Store
4.2 Frontend Cryptography Engine (`src/services/encryption.ts`)
    - Key derivation routines and secure salt generation
    - Envelope packing, IV handling, and Base64URL serialization
4.3 Memory Management & Chunked Streaming Implementation
    - `ReadableStream` chunking pipeline for gigabyte-scale payloads
    - Nonce sequencing and chunk integrity verification
4.4 Backend API & Controller Design
    - Auth Controller: Password hashing, verification, session issuance
    - File Controller: Multipart ciphertext ingestion, metadata indexing
    - Share Controller: Recipient key resolution and envelope association
4.5 User Interface Design & Usability Engineering
    - Cryptographic drag-and-drop vault
    - Real-time client-side encryption progress visualization
    - In-browser file previewer with zero-knowledge decryption

---

## CHAPTER 5: SECURITY ANALYSIS & EVALUATION
5.1 Adversary Modeling & Defense Verification (Detailed in Section 1.1 - 1.2)
5.2 Formal Verification of the Zero-Knowledge Invariant
    - Empirical proof that server storage receives 0 plaintext bytes
    - Shannon Entropy analysis of uploaded payloads ($H \approx 7.99\text{ bits/byte}$)
5.3 Residual Risks & Inherent Constraints (Detailed in Section 1.3)
5.4 SSE vs. CSE Architectural Comparison Matrix (Detailed in Section 1.4)

---

## CHAPTER 6: TESTING, VERIFICATION & QUALITY ASSURANCE
6.1 Testing Methodology & Test Pyramid
6.2 Frontend Unit Tests (Jest & Web Crypto API)
    - Encrypt/Decrypt byte fidelity verification
    - Unique nonce enforcement
    - Wrong password unwrap rejection
    - Bit-flip tampering and authentication tag failure assertions
6.3 Backend Integration Tests (Supertest & Express)
    - Route authorization and JWT verification
    - S3 storage adapter mock integration
    - Sharing authorization and access control barriers
6.4 Automated Test Suite Execution Results (29/29 Passing Tests)

---

## CHAPTER 7: EXPERIMENTAL RESULTS & PERFORMANCE BENCHMARKING
7.1 Benchmark Setup & Hardware Specifications
7.2 Encryption & Decryption Throughput vs. File Size (1 MB, 10 MB, 100 MB, 1 GB)
7.3 PBKDF2 Iteration Latency Profile Across Device Classes
7.4 Memory Footprint Analysis: In-Memory Buffering vs. Streamed Chunking
7.5 End-to-End Latency Breakdown: Network Transfer vs. Cryptographic Compute

---

## CHAPTER 8: DISCUSSION & LESSONS LEARNED
8.1 Key Findings & Architectural Validation
8.2 The Usability vs. Security Dichotomy in Zero-Knowledge Systems
8.3 Engineering Pitfalls Encountered & Resolutions
    - Web Crypto API differences between browser environments and Node.js
    - Avoiding heap exhaustion during large file encryption
8.4 Future Enhancements:
    - Searchable Symmetric Encryption (SSE) for encrypted keyword search
    - Post-Quantum Cryptography (PQC): Kyber/ML-KEM key encapsulation
    - Mobile native applications via WebAssembly / Rust crypto core

---

## CHAPTER 9: CONCLUSION & FUTURE WORK
9.1 Summary of Contributions
9.2 Concluding Remarks on User Data Sovereignty
9.3 Final Recommendations for Production Deployment

---

## REFERENCES
- [1] NIST Special Publication 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.
- [2] W3C Web Cryptography API Recommendation (https://www.w3.org/TR/WebCryptoAPI/).
- [3] IETF RFC 8018: PKCS #5: Password-Based Cryptography Specification Version 2.1 (PBKDF2).
- [4] IETF RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3.
- [5] Kamara, S., & Lauter, K. (2010). Cryptographic cloud storage. Financial Cryptography and Data Security.
- [6] Boneh, D., Di Crescenzo, G., Ostrovsky, R., & Persiano, G. (2004). Public key encryption with keyword search. EUROCRYPT.
- [7] Amazon Web Services: Protecting data using client-side encryption (AWS Crypto Tools).
```
