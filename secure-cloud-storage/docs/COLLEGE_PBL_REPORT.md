# PROJECT-BASED LEARNING (PBL) TECHNICAL REPORT
# SECURE CLOUD FILE STORAGE USING ENCRYPTION (AES-256-GCM)

**Department:** Department of Computer Science and Engineering — Cyber Security  
**Degree:** Bachelor of Technology (B.Tech in CSE - Cyber Security)  
**Academic Year:** 2026–2027 (Batch: 2023–2027)  
**Institution:** Geethanjali College of Engineering and Technology (UGC Autonomous Institution)  
*Accredited by NAAC with ‘A+’ Grade & NBA, Approved by AICTE, Affiliated to JNTUH*  
*Cheeryal (V), Keesara (M), Medchal (Dist), Telangana – 501 301.*

---

### Team Details: Team Number B6
1. **D. Pavani Reddy** — Roll No: **23R11A62A4**
2. **D. Alekhya Ashwini** — Roll No: **23R11A62A6**
3. **J. Lasya Priya** — Roll No: **23R11A62B6**

**Project Supervisor & Mentor:**  
**V. Soujenya**, Assistant Professor, Department of CSE – Cyber Security

**Head of Department:**  
**Dr. K. Krishna Jyothi**, Professor, Department of CSE – Cyber Security

---

## 1. ABSTRACT
Cloud computing enables users and enterprises to dynamically store, access, and manage digital files remotely. However, storing confidential files in third-party public cloud environments presents severe security challenges, including unauthorized insider access, data leakage, and silent tampering. Standard cloud storage often relies on Server-Side Encryption (SSE), wherein the cloud provider retains control of cryptographic keys and decrypts files transparently, creating an inherent single point of failure.

This project, titled **"Secure Cloud File Storage Using Encryption,"** implements an advanced, zero-trust cloud file storage system that guarantees data confidentiality, authenticity, and access control. Built using **Python**, **Flask**, and **SQLite**, the platform enforces **Envelope Encryption (NIST SP 800-57)** combined with **AES-256-GCM (NIST SP 800-38D)** Authenticated Encryption with Associated Data (AEAD). 

For every uploaded file:
1. A fresh 256-bit **Data Encryption Key (DEK)** is generated using a cryptographically secure pseudo-random number generator (CSPRNG).
2. The file is encrypted using AES-256-GCM with a unique 96-bit initialization vector (nonce) and protected with a 128-bit GHASH authentication tag.
3. The DEK itself is securely wrapped/encrypted with a tenant-isolated **Key Encryption Key (KEK)** derived via **PBKDF2-HMAC-SHA256 (100,000 rounds)**.
4. Plaintext integrity is independently tracked via a **SHA-256 cryptographic fingerprint**.

The architecture employs an extensible Storage Adapter supporting both an offline **Local Encrypted Storage Adapter** (zero-cost development mode) and an enterprise-grade **Amazon S3 Adapter** using **Boto3**. Multi-tenant isolation prevents Insecure Direct Object Reference (IDOR) attacks, while an integrated **Access Control Engine** supports time-bounded file sharing with automatic expiration and revocation. A comprehensive test suite comprising **20 automated Pytest test cases** validates tamper detection, envelope key wrapping, and access restrictions.

---

## 2. INTRODUCTION & MOTIVATION

### 2.1 Background
Public cloud infrastructure (e.g., Amazon S3, Google Cloud Storage, Microsoft Azure Blob) handles exabytes of sensitive academic, financial, and personal data. Under the cloud Shared Responsibility Model, the cloud provider manages infrastructure security, but data classification, access management, and encryption remain the customer's sole responsibility.

### 2.2 Shortcomings of Existing Systems
1. **Cloud Provider Key Dominance:** In typical Server-Side Encryption (e.g., AWS SSE-S3), the cloud provider holds the keys. A compromised AWS console or malicious insider grants access to raw plaintext.
2. **Lack of Authenticated Integrity in Legacy Ciphers:** Legacy block cipher modes such as AES-CBC or AES-ECB lack built-in integrity tags, leaving data vulnerable to bit-flipping and padding oracle attacks.
3. **Nonce Reuse Catastrophe:** Systems reusing initialization vectors in GCM mode suffer the "Forbidden Attack," destroying authenticity.
4. **Coarse-Grained Sharing:** Public file sharing frequently relies on unauthenticated, static public URLs, risking accidental exposure.

### 2.3 Proposed Solution
The proposed SecureCloud system enforces client-server application-level encryption:
- Files are encrypted before leaving the application layer.
- Strictly high-entropy ciphertext (`.enc`) is saved to disk or Amazon S3.
- Key hierarchy ensures zero master keys in cloud storage.
- Immediate rejection of modified or corrupted ciphertext during decryption.

---

## 3. SYSTEM ARCHITECTURE & 5-LAYER DESIGN

```
+-------------------------------------------------------------------------------+
| 1. USER INTERFACE LAYER (Browser)                                             |
|    - HTML5, CSS3, Bootstrap 5 (Dark Glassmorphic UI), Bootstrap Icons         |
|    - Responsive Vault Dashboard, Real-time Search, Share Modal with Expiry    |
+-------------------------------------------------------------------------------+
                                      | HTTPS (TLS 1.3)
                                      v
+-------------------------------------------------------------------------------+
| 2. APPLICATION CONTROLLER LAYER (Flask Blueprints)                            |
|    - Auth Blueprint (/auth): PBKDF2 Password Hashing, Session Management      |
|    - Files Blueprint (/files): Upload, Decrypt, Expiration, Revocation        |
|    - Security Blueprint (/security): Live Audit Dashboard, CSV Export         |
+-------------------------------------------------------------------------------+
             |                                             |
             v                                             v
+-----------------------------------------+   +---------------------------------+
| 3. AUTHENTICATION & ACCESS CONTROL      |   | 4. CRYPTOGRAPHIC & KEY ENGINE   |
|    - Multi-Tenant Ownership Checks      |   |    - AES-256-GCM AEAD Cipher    |
|    - Strict IDOR Protection (403 Abort) |   |    - Envelope Encryption:       |
|    - Time-Bounded Sharing Engine        |   |      * 256-bit Random DEK       |
|    - Expiration & Revocation Verifier   |   |      * KEK via PBKDF2 (100k)    |
|                                         |   |      * DEK Wrap via AES-GCM     |
|                                         |   |    - SHA-256 Plaintext Hash     |
+-----------------------------------------+   +---------------------------------+
             \                                             /
              v                                           v
+-------------------------------------------------------------------------------+
| 5. PERSISTENCE & STORAGE ADAPTER LAYER                                        |
|    +-----------------------------+     +----------------------------------+   |
|    | SQLite Metadata Database    |     | Storage Adapter Interface        |   |
|    | - Users & Salted Hashes     |     | - LocalStorageAdapter (Local)    |   |
|    | - Wrapped DEK + Nonces      |     | - S3StorageAdapter (Boto3 / AWS) |   |
|    | - File Nonce & Auth Tag     |     |                                  |   |
|    | - Time Shares & Audit Logs  |     | STORES ONLY CIPHERTEXT (.enc)    |   |
|    +-----------------------------+     +----------------------------------+   |
+-------------------------------------------------------------------------------+
```

### Module Descriptions
1. **User Interface Layer:** Allows users to view their encrypted vault, upload documents, inspect cryptographic metadata (IV, Tag, SHA-256), and manage shares.
2. **Application Controller Layer:** Handles routing, request validation, upload limits (25MB), and session cookies (`HttpOnly`, `SameSite=Lax`).
3. **Authentication & Access Control Layer:** Verifies identities, prevents horizontal privilege escalation (IDOR), and validates share timestamps.
4. **Cryptographic & Key Management Engine:** Executes envelope encryption, generates CSPRNG nonces, and evaluates 128-bit GHASH authentication tags.
5. **Storage Adapter Layer:** Pluggable interface abstracting physical persistence between private Amazon S3 buckets and local encrypted folders.

---

## 4. MATHEMATICAL & CRYPTOGRAPHIC FORMULATION

### 4.1 Galois/Counter Mode (AES-256-GCM)
Given plaintext $P$ of length $m$ blocks and 256-bit Data Encryption Key $K_{DEK}$:
1. **Counter Generation:** A 96-bit unique nonce $IV$ is concatenated with a 32-bit initial counter $0^{31}1$:
   $$Y_0 = IV \mathbin{\Vert} 0^{31}1$$
2. **Keystream Generation:** For each plaintext block $P_i$:
   $$C_i = P_i \oplus \text{AES}_{K_{DEK}}(Y_i) \quad \text{where } Y_i = \text{incr}(Y_{i-1})$$
3. **Authentication Tag Computation:** The 128-bit GHASH function evaluates a polynomial over the Galois field $\text{GF}(2^{128})$ using hash subkey $H = \text{AES}_{K_{DEK}}(0^{128})$:
   $$T = \text{GHASH}_H(AAD \mathbin{\Vert} C \mathbin{\Vert} \text{len}(AAD) \mathbin{\Vert} \text{len}(C)) \oplus \text{AES}_{K_{DEK}}(Y_0)$$
Any alteration to $C$, $AAD$, or $T$ causes GHASH recomputation to fail during decryption, throwing `InvalidTag`.

### 4.2 Envelope Encryption Pipeline
- **Step 1:** Generate $K_{DEK} \leftarrow \text{CSPRNG}(256\text{ bits})$.
- **Step 2:** Compute $C, IV_{file}, T_{file} \leftarrow \text{AES-GCM-Encrypt}(P, K_{DEK})$.
- **Step 3:** Derive $K_{KEK} \leftarrow \text{PBKDF2-HMAC-SHA256}(K_{master} \mathbin{\Vert} \text{"user\_"} \mathbin{\Vert} \text{user\_id}, \text{Salt}, 100000)$.
- **Step 4:** Wrap DEK: $W_{DEK}, IV_{wrap}, T_{wrap} \leftarrow \text{AES-GCM-Encrypt}(K_{DEK}, K_{KEK})$.
- **Step 5:** Discard plaintext $K_{DEK}$ from volatile memory immediately.

---

## 5. EXPERIMENTAL VERIFICATION & TEST RESULTS

The test suite was executed via **Pytest 9.2.0** on Python 3.13. All 20 automated tests passed with zero failures.

| Test Case Identifier | Test Module | Objective | Expected Outcome | Status |
| :--- | :--- | :--- | :--- | :--- |
| `test_user_registration` | `test_auth.py` | Verify salted password hash storage | Plaintext never saved; PBKDF2/scrypt verified | **PASSED** |
| `test_duplicate_registration_rejected` | `test_auth.py` | Prevent duplicate accounts | 400/Warning message displayed | **PASSED** |
| `test_login_success_and_session` | `test_auth.py` | Valid credentials authentication | Session established; Vault dashboard loaded | **PASSED** |
| `test_invalid_credentials_rejected` | `test_auth.py` | Wrong password rejection | Auth rejected; Failed audit log recorded | **PASSED** |
| `test_unauthenticated_dashboard_redirect` | `test_auth.py` | Protect private routes | 302 Redirect to `/auth/login` | **PASSED** |
| `test_aes_gcm_encryption_roundtrip` | `test_encryption.py` | End-to-end file encryption/decryption | Decrypted bytes match original exactly | **PASSED** |
| `test_empty_file_encryption` | `test_encryption.py` | Boundary case: 0-byte file | Handled gracefully without crash | **PASSED** |
| `test_binary_file_encryption` | `test_encryption.py` | Arbitrary binary payload (PDF/Images) | Complete binary structure preserved | **PASSED** |
| `test_unique_nonce_per_operation` | `test_encryption.py` | CSPRNG nonce uniqueness policy | Nonces strictly unique across runs | **PASSED** |
| `test_tampered_ciphertext_detection` | `test_encryption.py` | 1-bit flip in stored ciphertext | `InvalidTag` raised; Decryption aborted | **PASSED** |
| `test_tampered_auth_tag_detection` | `test_encryption.py` | Corrupted 128-bit MAC tag | `InvalidTag` raised; Zero data released | **PASSED** |
| `test_wrong_key_rejection` | `test_encryption.py` | Decryption attempt with incorrect key | `InvalidTag` raised; Access denied | **PASSED** |
| `test_envelope_encryption_dek_wrapping` | `test_encryption.py` | KEK/DEK wrapping and unwrapping | DEK unwrapped correctly; Tampering caught | **PASSED** |
| `test_sha256_plaintext_fingerprint` | `test_encryption.py` | Plaintext integrity digest | SHA-256 matches bit-for-bit | **PASSED** |
| `test_cross_user_file_access_denied` | `test_file_access.py` | IDOR prevention on download/delete | Returns 403 Forbidden | **PASSED** |
| `test_tampered_stored_ciphertext_rejection` | `test_file_integrity.py` | Real vault file corruption simulation | Security alert banner; Alert logged in audit | **PASSED** |
| `test_file_sharing_workflow` | `test_sharing.py` | Full share, download, revoke cycle | Share authorized; Revocation denies (403) | **PASSED** |
| `test_expired_share_denial` | `test_sharing.py` | Time-bounded share expiration | Expired link rejected with 403 Forbidden | **PASSED** |
| `test_file_details_api` | `test_sharing.py` | Safe cryptographic inspection API | Returns nonces, tags, SHA-256 without secrets | **PASSED** |
| `test_audit_logs_and_csv_export` | `test_sharing.py` | Security compliance & CSV export | CSV generated with full event audit trail | **PASSED** |

---

## 6. CONCLUSION & FUTURE ENHANCEMENTS

### 6.1 Conclusion
The **SecureCloud** platform demonstrates an enterprise-grade cloud file storage system that bridges theoretical cryptography and practical cloud engineering. By coupling **AES-256-GCM AEAD** with **Envelope Encryption (KEK/DEK)** and **SHA-256 verification**, the application ensures that plaintext data is never exposed to cloud infrastructure or unauthorized users. Multi-tenant access controls, time-bounded sharing, and audit logging provide defense-in-depth against insider threats, IDOR attacks, and silent data tampering.

### 6.2 Future Enhancements
1. **Client-Side WebCrypto API:** Migrate encryption to in-browser WebCrypto to achieve true End-to-End Encryption (E2EE).
2. **Hardware Security Module (HSM):** Integrate AWS Key Management Service (AWS KMS) or HashiCorp Vault for hardware-backed master key protection.
3. **Multi-Factor Authentication (MFA):** Implement TOTP (Time-based One-Time Passwords) via Google Authenticator.
4. **Chunked Streaming Encryption:** Support multi-gigabyte video uploads via authenticated chunk streaming.

---

## 7. REFERENCES
1. NIST FIPS Publication 197: *Advanced Encryption Standard (AES)*, 2001.
2. NIST Special Publication 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, 2007.
3. NIST Special Publication 800-57 Part 1 Rev. 5: *Recommendation for Key Management*, 2020.
4. NIST Special Publication 800-63B: *Digital Identity Guidelines: Authentication and Lifecycle Management*.
5. OWASP Foundation: *Application Security Verification Standard (ASVS)*, v4.0.3.
6. OWASP Cheat Sheet Series: *File Upload & Password Storage Security Cheat Sheets*.
7. Python Cryptographic Authority: *Cryptography Hazmat AEAD Documentation*, 2026.
8. Amazon Web Services: *Boto3 SDK Documentation: Amazon S3 Private Bucket Security*.
