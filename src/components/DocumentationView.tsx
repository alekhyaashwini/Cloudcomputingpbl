import React, { useState } from 'react';

export const DocumentationView: React.FC = () => {
  const [activeSection, setActiveSection] = useState<'report' | 'threat-model' | 'viva' | 'windows' | 'demo'>('threat-model');
  const [openVivaId, setOpenVivaId] = useState<number | null>(1);

  const vivaQuestions = [
    {
      id: 1,
      q: "What is AES-256-GCM, and why is it preferred over AES-CBC or AES-ECB?",
      a: "AES-256-GCM (Galois/Counter Mode) is an Authenticated Encryption with Associated Data (AEAD) algorithm. Unlike AES-ECB (which leaks data patterns) and AES-CBC (which provides confidentiality but is vulnerable to padding oracle attacks), GCM provides simultaneous confidentiality and data integrity using a 128-bit GHASH authentication tag in a single pass."
    },
    {
      id: 2,
      q: "What is an authentication tag, and how does it prevent tampering in cloud storage?",
      a: "The authentication tag is a 128-bit cryptographic Message Authentication Code (MAC) generated over the ciphertext using universal hashing in GF(2^128). During decryption, the receiver recomputes the tag. If even one bit of the ciphertext has been altered, the tags will not match, and decryption immediately halts with an InvalidTag exception."
    },
    {
      id: 3,
      q: "Why is Nonce/IV reuse catastrophic in AES-GCM (The Forbidden Attack)?",
      a: "In GCM mode, encrypting two different plaintexts with the same key and nonce reveals the XOR sum of the plaintexts. Even more dangerously, an adversary can algebraically solve for the GHASH hash key (H), allowing them to forge valid authentication tags for modified or arbitrary ciphertexts."
    },
    {
      id: 4,
      q: "What is the NIST-recommended Nonce length for AES-GCM?",
      a: "NIST Special Publication 800-38D explicitly recommends 96 bits (12 bytes). When using 12 bytes, the nonce is concatenated directly with the initial counter value (1) to construct the first counter block J_0 without requiring an extra GHASH operation."
    },
    {
      id: 5,
      q: "How are encryption keys managed in this project?",
      a: "We implement a hierarchical key derivation architecture using PBKDF2-HMAC-SHA256 with 100,000 iterations. Inputs include the Master Encryption Key, a unique 16-byte random salt generated per file, and the User ID. This guarantees tenant cryptographic isolation: no two files share the same derived key."
    },
    {
      id: 6,
      q: "What happens if the Master Encryption Key is lost?",
      a: "Because this is a zero-backdoor, zero-knowledge architecture, if the Master Key is lost, mathematically recovering the AES-256 key is impossible under modern computing limits (2^256 space). The stored files will become permanently undecryptable."
    },
    {
      id: 7,
      q: "How does the system prevent Path Traversal attacks during uploads and downloads?",
      a: "Filenames are sanitized using secure_filename() from Werkzeug. Furthermore, the storage adapter maps files to random UUID keys (e.g., enc_file_uuid.enc) rather than raw user-supplied paths, preventing '../' sequence traversal outside the authorized storage directory."
    },
    {
      id: 8,
      q: "How does the system enforce multi-user file isolation?",
      a: "Every file record in the SQLite database stores an owner_id linked to the users table. Whenever a download or delete endpoint is accessed, the backend verifies that the authenticated session user ID matches file.owner_id. If not, HTTP 403 Forbidden is returned."
    },
    {
      id: 9,
      q: "Why are user passwords hashed with PBKDF2 instead of encrypted?",
      a: "Encryption is two-way (reversible with a key), whereas hashing is one-way (irreversible). Passwords must never be reversible. Salted hashing with PBKDF2/scrypt ensures that even if the database leaks, an attacker cannot retrieve plaintext passwords or use precomputed rainbow tables."
    },
    {
      id: 10,
      q: "What is the storage overhead of AES-256-GCM?",
      a: "Because AES-GCM uses CTR mode, there is no block padding overhead. The ciphertext length equals the plaintext length. The only overhead is 12 bytes for the Nonce (IV) plus 16 bytes for the GHASH Authentication Tag, totaling just 28 bytes per file."
    },
    {
      id: 11,
      q: "What is the benefit of the Storage Adapter design pattern here?",
      a: "By abstracting storage behind the StorageAdapter interface, the application can switch between LocalStorageAdapter (for zero-cost offline college demonstration) and S3StorageAdapter (for real cloud deployment with Boto3) without modifying any application or encryption logic."
    },
    {
      id: 12,
      q: "What IAM permissions are required for least-privilege Amazon S3 integration?",
      a: "Only s3:PutObject, s3:GetObject, and s3:DeleteObject, strictly constrained to the specific bucket ARN (arn:aws:s3:::bucket-name/*). Administrative permissions like CreateBucket or DeleteBucket are excluded."
    },
    {
      id: 13,
      q: "What is a bit-flip attack, and how did your demonstration prove immunity?",
      a: "In unauthenticated ciphers like CBC or CTR, an attacker can modify specific ciphertext bits to predictably alter decrypted plaintext. In our tamper test, flipping 1 byte in the ciphertext caused the authentication tag recalculation to fail, immediately aborting decryption."
    },
    {
      id: 14,
      q: "What is Associated Data (AD) in AEAD?",
      a: "Associated Data is metadata that is authenticated (protected by the MAC tag) but left in plaintext. For example, binding the User ID or filename as Associated Data prevents an attacker from moving valid ciphertext into another user's account."
    },
    {
      id: 15,
      q: "How do you ensure AWS credentials are never exposed to the frontend?",
      a: "AWS Access Keys and Secret Keys are loaded server-side only from environment variables. All cloud operations are proxied through backend routes; the browser never receives or handles AWS credentials."
    }
  ];

  return (
    <div className="space-y-6">
      
      {/* Navigation tabs for Documentation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            College PBL Documentation & Viva Prep
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete academic project report, diagrams, viva voce practice, and faculty demo script.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveSection('threat-model')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
              activeSection === 'threat-model' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Architecture & Threat Model
          </button>
          <button
            onClick={() => setActiveSection('report')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
              activeSection === 'report' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Project Report
          </button>
          <button
            onClick={() => setActiveSection('viva')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
              activeSection === 'viva' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Viva Voce (Q&A)
          </button>
          <button
            onClick={() => setActiveSection('windows')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
              activeSection === 'windows' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Windows Setup
          </button>
          <button
            onClick={() => setActiveSection('demo')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer ${
              activeSection === 'demo' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-white'
            }`}
          >
            Faculty Demo Script
          </button>
        </div>
      </div>

      {/* SECTION: ARCHITECTURE & THREAT MODEL */}
      {activeSection === 'threat-model' && (
        <div className="space-y-6">
          
          {/* Header Card */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-3">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              Zero-Knowledge Client-Side Architecture
            </div>
            <h2 className="text-xl font-bold text-white">
              End-to-End Cryptographic Flow & Threat Model Analysis
            </h2>
            <p className="text-xs text-slate-300 leading-relaxed">
              In a true <strong>Zero-Knowledge system</strong>, the server, database, and cloud storage providers are classified as <em>untrusted entities</em>. Plaintext data and user passphrases are restricted exclusively to the client-side JavaScript execution context (W3C Web Cryptography API). All payloads transmitted across the network and persisted at rest consist solely of authenticated ciphertext.
            </p>
          </div>

          {/* Upload & Download Flow Diagram */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              1. Visual Sequence Flow: File Upload & Download
            </div>

            <div className="bg-black/60 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto leading-loose border border-slate-800">
{`========================================================================================================
                                       FILE UPLOAD SEQUENCE (ZERO-KNOWLEDGE)
========================================================================================================
[ USER BROWSER ]                     [ WEB CRYPTO API ]              [ EXPRESS API SERVER ]   [ MONGO / S3 ]
      |                                      |                                 |                    |
 1.   |-- Select File (Plaintext) ---------->|                                 |                    |
 2.   |-- User Master Passphrase ----------->|                                 |                    |
 3.   |                                      |-- Generate Salt (16B CSPRNG)    |                    |
 4.   |                                      |-- PBKDF2(Passphrase, Salt, 100k)|                    |
 5.   |                                      |   => 256-bit AES-GCM Key        |                    |
 6.   |                                      |-- Generate Nonce (12B CSPRNG)   |                    |
 7.   |                                      |-- AES-256-GCM Encrypt(Data, Key)|                    |
 8.   |                                      |   => Ciphertext + 16B MAC Tag   |                    |
 9.   |<-- [Ciphertext + IV + Tag + Salt] ---|                                 |                    |
10.   |                                                                        |                    |
      |======= POST /api/files/upload (ONLY CIPHERTEXT, ZERO PLAINTEXT) ======>|                    |
11.   |                                                                        |-- PutObject ------>| S3 / MinIO
      |                                                                        |   (Raw Ciphertext) | (Stored)
12.   |                                                                        |-- Save Metadata -->| MongoDB
      |                                                                        |   (IV, Tag, Salt)  | (Committed)
13.   |<================ HTTP 201 Created (Upload Success) ====================|                    |

========================================================================================================
                                 FILE DOWNLOAD & VERIFICATION SEQUENCE
========================================================================================================
[ USER BROWSER ]                     [ WEB CRYPTO API ]              [ EXPRESS API SERVER ]   [ MONGO / S3 ]
      |                                      |                                 |                    |
 1.   |======= GET /api/files/download/:id ===================================>|                    |
 2.   |                                                                        |-- Verify Owner --->| MongoDB
 3.   |                                                                        |-- GetObject ------>| S3 / MinIO
 4.   |<====== JSON: { base64Ciphertext, ivHex, saltHex, authTagHex } =========|                    |
 5.   |-- Passphrase + Salt + IV ----------->|                                 |                    |
 6.   |                                      |-- PBKDF2 Derive AES Key         |                    |
 7.   |                                      |-- AES-256-GCM Decrypt + Verify  |                    |
 8.   |                                      |   (Recalculates 128-bit GHASH)  |                    |
      |                                      +---------------------------------+                    |
      |                                      | Tag Matches?                    |                    |
      |                                      | YES => Output Plaintext Buffer  |                    |
      |                                      | NO  => OperationError (ABORT!)  |                    |
      |                                      +---------------------------------+                    |
 9.   |<-- Decrypted Plaintext File (or Error)                                                      |
10.   |-- Trigger Browser Blob Download File (Original Preserved)                                   |`}
            </div>

            {/* Mermaid Diagram */}
            <div>
              <div className="text-xs font-semibold text-slate-400 mb-1">Mermaid Sequence Diagram Specification:</div>
              <pre className="bg-slate-950/80 p-3 rounded text-[11px] font-mono text-slate-400 overflow-x-auto border border-slate-800">
{`sequenceDiagram
    autonumber
    actor User as User Browser (React)
    participant Crypto as Web Crypto API (Subtle)
    participant Server as Express API Server
    participant DB as MongoDB (Mongoose)
    participant S3 as Amazon S3 / MinIO

    Note over User,Crypto: CLIENT-SIDE ENCRYPTION (In-Browser)
    User->>Crypto: Input File Plaintext + Master Passphrase
    Crypto->>Crypto: 1. Generate 16-byte random salt
    Crypto->>Crypto: 2. Derive 256-bit AES key via PBKDF2 (100,000 rounds)
    Crypto->>Crypto: 3. Generate 96-bit CSPRNG nonce (IV)
    Crypto->>Crypto: 4. AES-256-GCM Encrypt => Ciphertext + 128-bit MAC Tag
    Crypto-->>User: Return Encrypted Payload (Ciphertext + IV + Tag + Salt)

    Note over User,Server: ZERO-KNOWLEDGE BOUNDARY (Network)
    User->>Server: POST /api/files/upload (Ciphertext, IV, Tag, Salt)
    Note over Server: Server never touches plaintext or keys!
    Server->>S3: PutObject(UUID.enc, Raw Ciphertext)
    Server->>DB: Insert File Document (ownerId, storageKey, ivHex, authTagHex, saltHex)
    Server-->>User: HTTP 201 Created

    Note over User,Server: DOWNLOAD & CLIENT-SIDE VERIFICATION
    User->>Server: GET /api/files/download/:id
    Server->>DB: Verify Ownership (ownerId == req.user.id)
    Server->>S3: GetObject(storageKey)
    Server-->>User: Stream Ciphertext + IV + Tag + Salt
    User->>Crypto: Decrypt(Ciphertext, Passphrase, Salt, IV)
    alt GHASH Tag Matches (Untampered)
        Crypto-->>User: Return Original Decrypted File
    else Bit-Flip / Tampering Detected
        Crypto-->>User: OperationError: Authentication Tag Mismatch (Decryption Aborted)
    end`}
              </pre>
            </div>
          </div>

          {/* Envelope Encryption Architecture & Rationale */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
              2. Envelope Encryption Architecture (DEK vs. KEK)
            </div>

            <h3 className="text-sm font-bold text-white">
              Two-Tier Key Hierarchy: Why Envelope Encryption Outperforms Direct Password Encryption
            </h3>

            <div className="bg-black/60 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed border border-slate-800">
{`+---------------------------------------------------------------------------------------------------+
|                                 ENVELOPE ENCRYPTION ARCHITECTURE                                 |
+---------------------------------------------------------------------------------------------------+
|  [ User File (Plaintext) ]                                                                        |
|              |                                                                                    |
|              v                                                                                    |
|       [ AES-256-GCM ] <------- (DEK: Data Encryption Key) [Fresh 256-bit random key per file]     |
|              |                                                                                    |
|              v                                                                                    |
|  [ File Ciphertext + Tag ] ===> Sent to S3 / Cloud Storage                                        |
|                                                                                                   |
|  ================================== KEY WRAPPING TIER =========================================  |
|                                                                                                   |
|  (DEK: Data Encryption Key)                                                                       |
|              |                                                                                    |
|              v                                                                                    |
|       [ AES-256-GCM Wrap ] <-- (KEK: Key Encryption Key) [Derived from user password via PBKDF2] |
|              |                                                                                    |
|              v                                                                                    |
|  [ Wrapped DEK + DEK IV ] ====> Stored in Database alongside File Metadata                        |
+---------------------------------------------------------------------------------------------------+`}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs mt-3">
              <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 space-y-1.5">
                <span className="font-bold text-cyan-300">1. Instant Password Change (Zero Re-encryption)</span>
                <p className="text-slate-300 leading-normal">
                  In direct encryption, changing a password requires downloading, decrypting, and re-encrypting every gigabyte of files. With envelope encryption, only the 32-byte DEK is re-wrapped with the new KEK—taking milliseconds regardless of file size.
                </p>
              </div>

              <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 space-y-1.5">
                <span className="font-bold text-emerald-300">2. Nonce Exhaustion & Multi-File Safety</span>
                <p className="text-slate-300 leading-normal">
                  AES-GCM requires that a key-nonce pair is NEVER repeated. In direct encryption, encrypting millions of blocks under one password key increases catastrophic collision risks. In envelope encryption, each file has a completely isolated key space.
                </p>
              </div>

              <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 space-y-1.5">
                <span className="font-bold text-amber-300">3. Multi-User Secure File Sharing</span>
                <p className="text-slate-300 leading-normal">
                  To share a file with Alice, Bob unwraps the file's DEK with his KEK and re-wraps it with Alice's public key (RSA-OAEP / ECDH). Alice decrypts the file without Bob ever having to share his master password.
                </p>
              </div>

              <div className="p-3 bg-slate-950/70 rounded-lg border border-slate-800 space-y-1.5">
                <span className="font-bold text-purple-300">4. Separation of Cryptographic Duties</span>
                <p className="text-slate-300 leading-normal">
                  DEKs are optimized for bulk streaming throughput (hardware AES-NI). The KEK is protected by expensive PBKDF2 (100,000 iterations), executed only once to unwrap the key.
                </p>
              </div>
            </div>
          </div>

          {/* Component-by-Component Deep Dive */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              3. Core Component Roles & Cryptographic Boundaries
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              
              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-indigo-400 font-mono text-sm">A. Client Application (React.js + Vite)</div>
                <p className="text-slate-300 leading-relaxed">
                  The client application acts as the security perimeter. It ingests user files into in-memory ArrayBuffers, prompts for the zero-knowledge master passphrase, coordinates the Web Crypto pipeline, and converts raw binary streams to and from base64/blobs. The client never leaks the master passphrase into DOM attributes or telemetry.
                </p>
              </div>

              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-emerald-400 font-mono text-sm">B. Cryptographic Engine (W3C Web Crypto API)</div>
                <p className="text-slate-300 leading-relaxed">
                  Operates using native browser assembly via <code className="text-emerald-300 font-mono">window.crypto.subtle</code>. Derives keys via PBKDF2-HMAC-SHA256 (100,000 rounds) and generates hardware-accelerated AES-256-GCM ciphertexts with 96-bit CSPRNG nonces. CryptoKey objects are flagged <code className="text-emerald-300 font-mono">extractable: false</code>, preventing memory dumping.
                </p>
              </div>

              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-amber-400 font-mono text-sm">C. API Server (Node.js + Express)</div>
                <p className="text-slate-300 leading-relaxed">
                  Provides stateless REST endpoints for identity management (JWT verification), tenant access control, and storage routing. Operates as a "blind proxy": it processes binary streams of ciphertext without attempting decryption, since it lacks the cryptographic keys.
                </p>
              </div>

              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-purple-400 font-mono text-sm">D. Metadata Store (MongoDB / SQLite)</div>
                <p className="text-slate-300 leading-relaxed">
                  Stores user accounts (salted bcrypt hashes) and cryptographic metadata necessary for decryption: 96-bit Nonce (IV), 128-bit Authentication Tag, 16-byte KDF Salt, and Cloud Object Keys. Contains zero encryption keys or plaintext passwords.
                </p>
              </div>

              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2 md:col-span-2">
                <div className="font-bold text-rose-400 font-mono text-sm">E. Cloud Object Storage (Amazon S3 / MinIO)</div>
                <p className="text-slate-300 leading-relaxed">
                  Persists high-entropy binary ciphertext blobs behind random UUID identifiers. Configured with private ACLs, bucket policies blocking all public access, and optional SSE-S3 encryption for defense-in-depth. S3 administrators inspect only high-entropy bytes with zero discernible plaintext structure.
                </p>
              </div>

            </div>
          </div>

          {/* Threat Model Analysis */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              4. Threat Model: Security Invariants & Attack Analysis
            </div>

            <div className="space-y-4 text-xs">
              
              {/* Protected Attacks Table */}
              <div>
                <h4 className="font-bold text-emerald-400 mb-2 text-sm">
                  ✓ What This Zero-Knowledge Design Protects Against
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse border border-slate-800">
                    <thead className="bg-slate-950 text-slate-400 font-mono">
                      <tr>
                        <th className="p-2.5 border border-slate-800">Threat / Attack Vector</th>
                        <th className="p-2.5 border border-slate-800">Adversary Goal</th>
                        <th className="p-2.5 border border-slate-800">System Defense & Cryptographic Mechanism</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Malicious Cloud Insider (AWS Admin)</td>
                        <td className="p-2.5">Inspect files stored on cloud disks</td>
                        <td className="p-2.5">Data stored in S3 is AES-256-GCM ciphertext. Without the user's master passphrase (which never leaves the client), the files are mathematically indecipherable ($2^{256}$ brute-force space).</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Database Breach (Stolen MongoDB / SQLite)</td>
                        <td className="p-2.5">Decrypt files using leaked database records</td>
                        <td className="p-2.5">Database contains only metadata (Nonce, Salt, Tag, S3 key). It stores NO encryption keys and NO plaintext passwords (only salted hashes). Stealing the database reveals zero file content.</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Man-in-the-Middle (MITM) / TLS Termination</td>
                        <td className="p-2.5">Sniff plaintext during HTTP transmission</td>
                        <td className="p-2.5">Because encryption occurs client-side prior to network dispatch, even an adversary with an unauthorized TLS proxy certificate sees only ciphertext payloads.</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Ciphertext Bit-Flipping / Tampering Attack</td>
                        <td className="p-2.5">Modify file content in S3 bucket</td>
                        <td className="p-2.5">AES-256-GCM includes a 128-bit GHASH authentication tag. Any single-bit corruption causes tag recomputation to fail during client decryption, immediately halting execution with <code className="text-rose-400 font-mono">OperationError</code>.</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Cross-Tenant Privilege Escalation</td>
                        <td className="p-2.5">User B attempts to download User A's file</td>
                        <td className="p-2.5">1. Express enforces tenant isolation (<code className="font-mono">ownerId === req.user._id</code>).<br />2. Even if bypassed, User B lacks User A's master passphrase, causing GCM tag authentication to fail.</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Nonce-Reuse Keystream Attack</td>
                        <td className="p-2.5">Recover plaintext XOR or GHASH key</td>
                        <td className="p-2.5">A fresh 96-bit CSPRNG nonce is generated for every single upload via <code className="font-mono text-emerald-400">crypto.getRandomValues()</code>, eliminating nonce-reuse vulnerabilities.</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Unprotected Scenarios Table */}
              <div className="pt-3">
                <h4 className="font-bold text-rose-400 mb-2 text-sm">
                  ⚠️ What This Design Does NOT Protect Against (Residual Risks & Compensating Controls)
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse border border-slate-800">
                    <thead className="bg-slate-950 text-slate-400 font-mono">
                      <tr>
                        <th className="p-2.5 border border-slate-800">Attack Vector / Limitation</th>
                        <th className="p-2.5 border border-slate-800">Why It Bypasses Cryptography</th>
                        <th className="p-2.5 border border-slate-800">Industry Compensating Controls</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-slate-300">
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Compromised Client Endpoint (Keylogger / Malware)</td>
                        <td className="p-2.5">If the user's laptop has a keylogger or infostealer malware, the adversary captures the master passphrase as it is typed into the browser.</td>
                        <td className="p-2.5">Endpoint Detection and Response (EDR), hardware security keys (FIDO2/WebAuthn), and OS-level memory isolation.</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Lost Master Passphrase (Zero-Backdoor)</td>
                        <td className="p-2.5">Because no master key or recovery backdoor exists on the server, a forgotten passphrase renders all encrypted files mathematically unrecoverable.</td>
                        <td className="p-2.5">Shamir's Secret Sharing (M-of-N key threshold split) or offline cryptographic recovery kits (BIP-39 mnemonic seed phrases).</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Traffic Analysis & File Size Leakage</td>
                        <td className="p-2.5">AES-GCM is a stream cipher mode; ciphertext size equals plaintext size (plus 28 bytes). An observer can infer document types from file lengths.</td>
                        <td className="p-2.5">Fixed-block cryptographic padding (e.g. padding all uploads to multiples of 1MB or 5MB).</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Malicious Browser Extensions / XSS</td>
                        <td className="p-2.5">A rogue browser extension or Cross-Site Scripting (XSS) payload can read memory within the web page origin before WebCrypto derives keys.</td>
                        <td className="p-2.5">Strict Content Security Policy (CSP), subresource integrity (SRI), and forbidding untrusted browser plugins.</td>
                      </tr>
                      <tr>
                        <td className="p-2.5 font-semibold text-white">Denial of Service (Storage Deletion / Exhaustion)</td>
                        <td className="p-2.5">An attacker with administrative cloud access could delete ciphertext blobs or flood the bucket with spam uploads.</td>
                        <td className="p-2.5">S3 Object Lock (WORM - Write Once Read Many), Multi-Factor Authentication (MFA) Delete, and rate limiting.</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

            </div>
          </div>

        </div>
      )}

      {/* SECTION 1: PROJECT REPORT */}
      {activeSection === 'report' && (
        <div className="space-y-6">
          
          {/* Abstract Card */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-3">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              Project Abstract
            </div>
            <h3 className="text-lg font-bold text-white">
              Secure Cloud File Storage Using Authenticated Encryption (AES-256-GCM)
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed">
              In modern cloud computing, storing sensitive personal and organizational files in third-party public cloud environments (such as Amazon S3 or Google Cloud) presents inherent security challenges. Plaintext data at rest is susceptible to internal provider threats, credential theft, and unauthorized regulatory inspection.
            </p>
            <p className="text-xs text-slate-300 leading-relaxed">
              This Project-Based Learning (PBL) project addresses these threats by engineering a secure web application that performs <strong>AES-256-GCM authenticated encryption</strong> prior to transmitting files to cloud storage. Cryptographic keys are derived hierarchically using PBKDF2-HMAC-SHA256 with 100,000 rounds and per-file salts, enforcing strict multi-tenant isolation. A storage abstraction layer supports both a local encrypted vault and Amazon S3 via Boto3. Built-in tamper detection mathematically guarantees that any unauthorized alteration to stored ciphertext causes immediate verification failure.
            </p>
          </div>

          {/* Architecture & Flow Diagram */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              System Architecture & Data Flow
            </div>
            
            {/* Visual Flow Blocks */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              
              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-indigo-400 font-mono">1. User & Authentication Layer</div>
                <ul className="list-disc list-inside text-slate-300 space-y-1">
                  <li>User Registration & Login</li>
                  <li>PBKDF2 / scrypt password hashing</li>
                  <li>Session-based access control</li>
                  <li>Role & Tenant isolation verification</li>
                </ul>
              </div>

              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-emerald-400 font-mono">2. Cryptographic Engine</div>
                <ul className="list-disc list-inside text-slate-300 space-y-1">
                  <li>Master Key (KEK) + User ID</li>
                  <li>16-byte random salt generation</li>
                  <li>96-bit CSPRNG Nonce per file</li>
                  <li>AES-256-GCM (128-bit MAC tag)</li>
                </ul>
              </div>

              <div className="p-4 bg-slate-950/60 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-amber-400 font-mono">3. Dual Storage Backend</div>
                <ul className="list-disc list-inside text-slate-300 space-y-1">
                  <li>Amazon S3 Cloud Adapter (Boto3)</li>
                  <li>Local Encrypted Vault Adapter</li>
                  <li>Strictly ciphertext on disk/cloud</li>
                  <li>Zero plaintext storage guarantee</li>
                </ul>
              </div>

            </div>

            {/* DFD ASCII block */}
            <div className="bg-black/60 p-4 rounded-lg font-mono text-xs text-slate-300 overflow-x-auto leading-loose border border-slate-800">
{`DFD Level 0 (Context Diagram):
[ User Client ] ---> (Auth Credentials / Plaintext File Upload) ---> [ 0.0 Secure Cloud Storage System ]
[ User Client ] <--- (Session Token / Decrypted File Stream / Alerts) <--- [ 0.0 Secure Cloud Storage System ]
                                                                                |
                                               +--------------------------------+--------------------------------+
                                               |                                                                 |
                                               v                                                                 v
                             [ Amazon S3 / Local Vault ]                                             [ SQLite Metadata DB ]
                           (Stores Strictly Ciphertext)                                            (Stores Nonce, Tag, Salt)`}
            </div>
          </div>

          {/* Database Schema */}
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              Relational Database Schema (SQLite)
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 space-y-1">
                <div className="text-indigo-400 font-bold mb-1">TABLE: users</div>
                <div>id: INTEGER PRIMARY KEY</div>
                <div>username: TEXT UNIQUE</div>
                <div>email: TEXT UNIQUE</div>
                <div>password_hash: TEXT (PBKDF2/scrypt)</div>
                <div>created_at: TIMESTAMP</div>
              </div>

              <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 space-y-1">
                <div className="text-emerald-400 font-bold mb-1">TABLE: files</div>
                <div>id: INTEGER PRIMARY KEY</div>
                <div>owner_id: INTEGER (FK → users.id)</div>
                <div>original_name: TEXT</div>
                <div>original_size / encrypted_size: INT</div>
                <div>nonce_hex: TEXT (24 hex chars)</div>
                <div>auth_tag_hex: TEXT (32 hex chars)</div>
                <div>salt_hex: TEXT (32 hex chars)</div>
                <div>storage_backend / storage_key: TEXT</div>
              </div>
            </div>
          </div>

        </div>
      )}

      {/* SECTION 2: VIVA VOCE QUESTIONS & ANSWERS */}
      {activeSection === 'viva' && (
        <div className="space-y-4">
          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800">
            <h3 className="text-base font-bold text-white">
              Faculty Viva Voce Preparation Guide (15 Core Questions)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Click any question to view the comprehensive, high-scoring technical explanation.
            </p>
          </div>

          <div className="space-y-2">
            {vivaQuestions.map((item) => (
              <div
                key={item.id}
                className="bg-slate-900/40 border border-slate-800 rounded-lg overflow-hidden"
              >
                <button
                  onClick={() => setOpenVivaId(openVivaId === item.id ? null : item.id)}
                  className="w-full text-left p-3.5 text-xs font-semibold text-slate-200 hover:text-white hover:bg-slate-800/40 transition-colors flex items-center justify-between cursor-pointer"
                >
                  <span className="flex items-center gap-2">
                    <span className="text-indigo-400 font-mono">Q{item.id}.</span>
                    <span>{item.q}</span>
                  </span>
                  <span className="text-slate-500 font-mono">{openVivaId === item.id ? '−' : '+'}</span>
                </button>

                {openVivaId === item.id && (
                  <div className="p-4 pt-1 text-xs text-slate-300 leading-relaxed border-t border-slate-800/60 bg-slate-950/40">
                    <strong className="text-emerald-400">Model Answer: </strong>
                    {item.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECTION 3: WINDOWS SETUP INSTRUCTIONS */}
      {activeSection === 'windows' && (
        <div className="space-y-4">
          <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              Windows 10 / 11 PowerShell Instructions
            </div>
            <h3 className="text-lg font-bold text-white">
              Running the Python Flask Application on Windows
            </h3>
            <p className="text-xs text-slate-300">
              Ensure you have Python 3.11+ installed from python.org with "Add python.exe to PATH" checked.
            </p>

            <div className="space-y-4 text-xs font-mono">
              
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div className="text-slate-400 mb-1"># 1. Open PowerShell and navigate to the project directory:</div>
                <div className="text-emerald-400">cd secure-cloud-storage</div>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div className="text-slate-400 mb-1"># 2. Automated Run (Easiest way):</div>
                <div className="text-emerald-400">Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass</div>
                <div className="text-emerald-400">.\run_windows.ps1</div>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div className="text-slate-400 mb-1"># 3. Manual Step-by-Step Setup:</div>
                <div className="text-slate-300">python -m venv venv</div>
                <div className="text-slate-300">.\venv\Scripts\Activate.ps1</div>
                <div className="text-slate-300">pip install -r requirements.txt</div>
                <div className="text-slate-300">Copy-Item .env.example .env</div>
                <div className="text-slate-300">pytest -v</div>
                <div className="text-emerald-400">python app.py</div>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                <div className="text-slate-400 mb-1"># 4. Open in Web Browser:</div>
                <div className="text-indigo-400">http://127.0.0.1:5000</div>
              </div>

            </div>
          </div>
        </div>
      )}

      {/* SECTION 4: FACULTY DEMO SCRIPT */}
      {activeSection === 'demo' && (
        <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
          <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
            Faculty Evaluation Walkthrough
          </div>
          <h3 className="text-lg font-bold text-white">
            5-Minute Demonstration Script for Project Viva / Review
          </h3>

          <div className="space-y-4 text-xs text-slate-300">
            
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <strong className="text-indigo-400 font-mono">Step 1: Introduction & Architecture (1 min)</strong>
              <p className="mt-1">
                "Good morning, professors. Our project is titled 'Secure Cloud File Storage Using Authenticated Encryption.' Traditional cloud storage relies on server-side encryption where the provider retains the keys. Our application encrypts file contents with AES-256-GCM using unique 96-bit nonces before transmission, guaranteeing zero-trust storage."
              </p>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <strong className="text-indigo-400 font-mono">Step 2: Demonstrate Encrypted Upload (1 min)</strong>
              <p className="mt-1">
                "I will now upload a confidential PDF. Observe that the file receives a fresh 96-bit Nonce and 16-byte Authentication Tag. If we inspect the storage directory or S3 bucket, the file contains zero readable ASCII plaintext."
              </p>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <strong className="text-indigo-400 font-mono">Step 3: Successful Decryption (1 min)</strong>
              <p className="mt-1">
                "Clicking 'Decrypt & Download' recalculates the 128-bit GHASH tag. Since the tag matches, AES-256-GCM authenticates the ciphertext and restores the original file perfectly."
              </p>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <strong className="text-rose-400 font-mono">Step 4: The Core Security Test — Tamper Detection (1.5 mins)</strong>
              <p className="mt-1">
                "Now, to prove our integrity guarantee, I will click 'Corrupt 1 Byte' (simulating an adversary modifying data in the cloud bucket). When we attempt to download the corrupted file, the GCM authentication tag verification immediately catches the discrepancy and aborts decryption with a security alert, preventing corrupted data injection."
              </p>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800">
              <strong className="text-emerald-400 font-mono">Step 5: Automated Test Execution (30 secs)</strong>
              <p className="mt-1">
                "Finally, our automated pytest suite verifies 13 security test cases covering empty files, binary streams, cross-user isolation, and wrong-key rejection."
              </p>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
