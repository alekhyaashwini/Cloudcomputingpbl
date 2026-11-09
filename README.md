# SECUREVAULT: Secure Cloud File Storage Using Advanced Encryption

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Cryptography: AES--256--GCM](https://img.shields.io/badge/Cipher-AES--256--GCM-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Standards: NIST SP 800--57](https://img.shields.io/badge/Key_Model-Envelope_Encryption-purple.svg)](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
[![Cloud: Amazon S3](https://img.shields.io/badge/Storage-Amazon_S3_%2B_Local-orange.svg)](https://aws.amazon.com/s3/)
[![Security Tests: 52 Passed](https://img.shields.io/badge/Security_Tests-52%2F52_Passing-brightgreen.svg)]()

> **A Zero-Knowledge Cloud Storage Application** engineered with **Client-Side AES-256-GCM Authenticated Encryption**, **NIST SP 800-57 Envelope Key Wrapping**, **Asymmetric RSA-OAEP Key Re-Wrapping for Multi-User Sharing**, and **Dual-Backend Storage Adapters (Amazon S3 & Local Vault)**.

---

## 📌 Project Overview

In traditional cloud storage architectures, files are uploaded in plaintext and encrypted on the cloud provider's servers (Server-Side Encryption). Under that model, cloud infrastructure administrators, hypervisor compromises, or misconfigured storage permissions expose confidential files in plaintext.

**SECUREVAULT** solves this fundamental cloud security challenge by enforcing **Zero-Knowledge Client-Side Cryptography**:
1. Files are encrypted **inside the user's browser runtime** using the official **W3C Web Cryptography API** (`window.crypto.subtle`) before any byte leaves the machine.
2. The cloud server and database receive **strictly high-entropy binary ciphertext (`.enc`)**, wrapped encryption keys, 96-bit initialization vectors (IVs), and 128-bit GHASH authentication tags.
3. The cloud service provider has **zero visibility into plaintext contents or master encryption keys**.

---

## 🎓 Academic Credentials

* **Institution:** Geethanjali College of Engineering and Technology (UGC Autonomous Institution)
* **Accreditation:** NAAC with 'A+' Grade & NBA Accredited, Approved by AICTE, Affiliated to JNTUH
* **Department:** Department of Computer Science and Engineering — Cyber Security
* **Degree:** Bachelor of Technology (B.Tech in CSE - Cyber Security)
* **Academic Year:** 2026–2027 (Batch: 2023–2027)

### Project Team (Team Number: B6)
| Student Name | Hall Ticket Number | Department |
| :--- | :--- | :--- |
| **D. Pavani Reddy** | `23R11A62A4` | CSE - Cyber Security |
| **D. Alekhya Ashwini** | `23R11A62A6` | CSE - Cyber Security |
| **J. Lasya Priya** | `23R11A62B6` | CSE - Cyber Security |

* **Project Supervisor & Mentor:** **V. Soujenya**, Assistant Professor, Dept of CSE – Cyber Security
* **Head of the Department:** **Dr. K. Krishna Jyothi**, Professor, Dept of CSE – Cyber Security

---

## 🌐 Project Website & Repositories

* **Source Code Repository:** [https://github.com/alekhyaashwini/Cloudcomputingpbl](https://github.com/alekhyaashwini/Cloudcomputingpbl)
* **Local Web Application Portal:** [http://localhost:3000](http://localhost:3000) (Interactive Full-Stack WebCrypto Application)
* **Python Cloud Vault Portal:** [http://127.0.0.1:5000](http://127.0.0.1:5000) (Flask/FastAPI Backend Service)

---

## 🏛️ System Architecture

```
+---------------------------------------------------------------------------------------+
| 1. PRESENTATION LAYER (Client Browser)                                                |
|    - React 19, TypeScript, Tailwind CSS, Lucide React Icons                           |
|    - Responsive Glassmorphic Dashboard, Search & Filter, Cryptographic Inspector     |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| 2. ZERO-KNOWLEDGE CRYPTOGRAPHIC ENGINE (W3C Web Crypto API)                           |
|    - 256-bit AES-GCM (NIST SP 800-38D): High-performance Authenticated Encryption.   |
|    - 96-bit Nonce Policy: Cryptographically secure random IV generated per file.      |
|    - 128-bit GHASH Authentication Tag: Validates file authenticity upon decryption.   |
|    - PBKDF2-HMAC-SHA256 (100,000 rounds): Key Encryption Key (KEK) derivation.        |
|    - Asymmetric RSA-OAEP (2048-bit): Multi-user zero-knowledge DEK re-wrapping.       |
|    - SHA-256 Fingerprint: Plaintext integrity verification before & after encryption. |
+---------------------------------------------------------------------------------------+
                                           |
                     HTTPS / TLS 1.3 (Ciphertext Buffers + Metadata)
                                           v
+---------------------------------------------------------------------------------------+
| 3. APPLICATION & ACCESS CONTROL CONTROLLER (REST API)                                 |
|    - Session & JWT Authentication: Salted credential storage, brute-force defense.    |
|    - Multi-Tenant Isolation: Server-side ownership verification (Strict IDOR Defense).|
|    - Time-Bounded Sharing Engine: Granular share duration, auto-expiry, revocation.  |
|    - Immutable Audit Logging: Append-only security log with CSV export capability.    |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| 4. STORAGE PERSISTENCE ADAPTER                                                        |
|    - LocalStorageAdapter: Filesystem persistence storing strictly raw ciphertext.     |
|    - S3StorageAdapter: Amazon S3 Private Bucket integration using official AWS SDK.   |
|    ==> Zero Plaintext files or master keys ever touch storage or database tables!     |
+---------------------------------------------------------------------------------------+
```

---

## 🔒 Key Cryptographic Features

### 1. NIST SP 800-57 Envelope Encryption
* **Data Encryption Key (DEK):** A unique 256-bit symmetric key (`crypto.getRandomValues`) generated per file.
* **Key Encryption Key (KEK):** Derived from the user's master password using **PBKDF2-HMAC-SHA256 with 100,000 iterations** and a 16-byte random salt.
* **Key Wrapping:** The DEK is encrypted with the KEK using AES-256-GCM. Rotating master passwords requires only re-wrapping the small 32-byte DEK rather than re-encrypting entire file contents.

### 2. Dual-Layer Cryptographic Integrity Verification
* **Layer 1 (GHASH MAC Tag):** AES-GCM evaluates a 128-bit polynomial tag over the ciphertext. If any bit in storage is modified, decryption immediately halts.
* **Layer 2 (SHA-256 Digest):** A SHA-256 checksum is computed from the plaintext before encryption and verified post-decryption to guarantee bit-for-bit fidelity.

### 3. Asymmetric Zero-Knowledge File Sharing (RSA-OAEP)
* When Alice shares a file with Bob, Alice's browser retrieves Bob's public RSA-OAEP key.
* Alice's browser decrypts the DEK using her KEK, immediately re-wraps it with Bob's public key, and sends the re-wrapped envelope to the server.
* Bob decrypts the DEK using his client-side private key. The server never observes the raw DEK or plaintext.

### 4. Interactive Cryptographic Tamper Lab
* Built-in security demonstration interface allowing evaluators to deliberately flip a single bit in stored ciphertext.
* Decryption immediately triggers an **`InvalidTag`** rejection and displays a critical security alert banner, verifying that corrupted data is never delivered.

---

## ⚡ Quick Start Guide (Windows PowerShell)

### Prerequisites
* **Node.js** (v18+ or v20+ LTS) — [nodejs.org](https://nodejs.org)
* **Python** (v3.11+ or v3.13) — [python.org](https://python.org)

### Method 1: All-in-One Launcher (Recommended)
Clone the repository and run the PowerShell launcher:
```powershell
git clone https://github.com/alekhyaashwini/Cloudcomputingpbl.git
cd Cloudcomputingpbl
.\run_project.ps1
```
Select:
* **`[1]`** to launch the full-stack WebCrypto React application at `http://localhost:3000`.
* **`[2]`** to launch the Python Flask encrypted vault at `http://127.0.0.1:5000`.
* **`[3]`** to run the complete 52-test automated verification suite.

---

### Method 2: Manual Step-by-Step Execution

#### Option A: Running the React + Web Crypto Full-Stack App
```powershell
# 1. Install dependencies
npm install --legacy-peer-deps

# 2. Build production assets
npm run build

# 3. Start the application server
npm run dev
```
Open your browser to: **`http://localhost:3000`**  
*(Default demo credentials: `student@college.edu` / `Student@123`)*

#### Option B: Running the Python Cryptographic Vault
```powershell
cd secure-cloud-storage
python -m venv --system-site-packages venv
.\venv\Scripts\python.exe app.py
```
Open your browser to: **`http://127.0.0.1:5000`**

---

## 🧪 Comprehensive Automated Testing (52/52 Tests Passing)

The project includes unit, integration, and security tests covering all cryptographic invariants.

```powershell
# 1. Run Frontend Web Crypto Unit Tests (Jest - 16 Tests)
npm run test:frontend

# 2. Run Backend REST API Integration Tests (Supertest - 16 Tests)
npm run test:backend

# 3. Run Python Envelope Encryption Tests (Pytest - 20 Tests)
cd secure-cloud-storage
.\venv\Scripts\pytest.exe -v
```

### Verification Matrix Summary
| Test Category | Suite | Test Cases | Status |
| :--- | :--- | :---: | :---: |
| **Web Crypto API & Envelope Encryption** | Jest (`tests/frontend/encryption.test.js`) | 16 | **16 / 16 PASSED** |
| **Zero-Knowledge Backend API & S3 Mock** | Supertest (`tests/backend/api.test.js`) | 16 | **16 / 16 PASSED** |
| **Python AES-GCM & Audit Security** | Pytest (`secure-cloud-storage/tests/`) | 20 | **20 / 20 PASSED** |
| **Total Automated Test Coverage** | **All Modules** | **52** | **52 / 52 PASSED (100%)** |

---

## 📁 Repository Directory Structure

```
Cloudcomputingpbl/
├── docs/                                # Academic Reports & Demonstration Guides
│   ├── SECUREVAULT_FACULTY_GUIDE.md     # Faculty Demo Script & Model Viva Q&A
│   ├── COLLEGE_PBL_REPORT.md            # Formal B.Tech Project Report & Architecture
│   └── diagrams/                        # 5-Layer Security & Workflow Diagrams
│
├── src/                                 # Zero-Knowledge Frontend (React 19 + TypeScript)
│   ├── components/
│   │   ├── DashboardView.tsx            # Main Vault Interface
│   │   ├── TamperLabView.tsx            # Live Ciphertext Bit-Flip Simulator
│   │   ├── CryptoInspectorModal.tsx     # 96-bit Nonce, 128-bit Tag & SHA-256 Inspector
│   │   ├── TestMatrixView.tsx           # Automated Test Status Dashboard
│   │   └── StorageConfigModal.tsx       # Amazon S3 / Local Storage Switcher
│   ├── services/
│   │   ├── webCrypto.ts                 # W3C Web Cryptography API Core (AES-256-GCM)
│   │   └── encryption.js                # Envelope & Asymmetric RSA-OAEP Key Re-Wrapping
│   └── App.tsx                          # Primary React Router & Application Hub
│
├── server.ts                            # Full-Stack Application Server (Vite + Express)
├── package.json                         # Node.js Dependencies & Test Scripts
├── run_project.ps1                      # Windows PowerShell Master Launcher
│
├── secure-cloud-storage/                # Python Cryptographic Backend
│   ├── app/
│   │   ├── auth/routes.py               # Authentication & Salted PBKDF2 Password Hashing
│   │   ├── files/routes.py              # Upload, Decrypt, Time-Bounded Sharing
│   │   ├── security/routes.py           # Security Audit Dashboard & CSV Export
│   │   ├── services/encryption.py       # Python AES-256-GCM AEAD Engine
│   │   ├── services/key_management.py   # Envelope Encryption & KEK Derivation
│   │   └── services/storage.py          # Storage Adapter (Amazon S3 + Local Vault)
│   └── tests/                           # Pytest Security Test Suite (20 Tests)
│
└── tests/                               # Jest Full-Stack Test Suite (32 Tests)
    ├── frontend/encryption.test.js      # Client-side WebCrypto Invariant Tests
    └── backend/api.test.js              # REST API & Zero-Knowledge Storage Tests
```

---

## 🛡️ Cloud Security & Threat Mitigation Summary

| Threat / Vulnerability | Underlying Risk | SECUREVAULT Mitigation |
| :--- | :--- | :--- |
| **Cloud Storage Exposure** | Public S3 bucket misconfiguration leaks files | Client-side AES-256-GCM encryption before upload; zero plaintext stored |
| **Ciphertext Modification** | Man-in-the-middle or insider tampering | 128-bit GHASH tag verification immediately rejects corrupted files |
| **Nonce Reuse Attack** | Reusing GCM IVs breaks authenticity | 96-bit CSPRNG nonces generated uniquely for every encryption operation |
| **Insecure Direct Object Reference (IDOR)** | User accesses another user's file via ID | Server-side database ownership checks enforce strict `403 Forbidden` |
| **Credential Theft** | Password cracking via dictionary attacks | Argon2id / PBKDF2-HMAC-SHA256 salted password hashing (100,000 rounds) |
| **Insecure Sharing** | Sending raw keys over URLs | Asymmetric RSA-OAEP key re-wrapping; recipient decrypts with private key |
| **Unauthorized Action Tampering** | Covering attacker traces | Append-only security audit log recording actors, IP addresses, and events |

---

## 📜 References & Regulatory Standards

1. **NIST SP 800-38D:** *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, National Institute of Standards and Technology.
2. **NIST SP 800-57 Part 1 Rev. 5:** *Recommendation for Key Management*, NIST Information Technology Laboratory.
3. **W3C Web Cryptography API:** *W3C Recommendation for Browser-Native Cryptography*, World Wide Web Consortium.
4. **OWASP ASVS v4.0.3:** *Application Security Verification Standard*, Open Web Application Security Project.
5. **RFC 8018:** *PKCS #5: Password-Based Cryptography Specification Version 2.1 (PBKDF2)*.
