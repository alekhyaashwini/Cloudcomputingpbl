# Secure Cloud File Storage Using Authenticated Encryption (AES-256-GCM)

A comprehensive B.Tech Computer Science Project-Based Learning (PBL) project implementing authenticated client-cloud file protection using AES-256-GCM, PBKDF2-HMAC key management, multi-tenant isolation, SQLite, and an Amazon S3 / Local Vault storage abstraction.

---

## 1. Project Overview

Cloud storage providers operate under a shared responsibility model. Plaintext files stored in cloud environments are vulnerable to insider threats, infrastructure compromises, and man-in-the-middle tampering. This project solves that vulnerability by encrypting all file content using **AES-256-GCM** (Galois/Counter Mode) *before* data reaches the storage backend.

### Key Highlights
- **Authenticated Encryption (AEAD):** AES-256-GCM provides both confidentiality and data authenticity using a 128-bit GHASH authentication tag.
- **NIST Nonce Policy:** Every file encryption uses a fresh, cryptographically secure 96-bit (12-byte) pseudo-random nonce (`secrets.token_bytes(12)`).
- **Zero Plaintext at Rest:** Cloud and local storage repositories store strictly ciphertext.
- **Key Management & Tenant Isolation:** Per-user and per-file symmetric keys derived via PBKDF2-HMAC-SHA256 (100,000 iterations).
- **Dual Storage Abstraction:** Seamlessly switch between a zero-cost Local Encrypted Vault and Amazon S3 with Boto3.
- **Automated Tamper Detection:** Any alteration to ciphertext or authentication tags in storage triggers an immediate `InvalidTag` rejection.

---

## 2. Architecture & Cryptographic Flow

```
+--------------------------------------------------------------------------+
|                            USER BROWSER                                  |
+--------------------------------------------------------------------------+
                                  |
                 HTTPS / Session Authenticated Upload
                                  v
+--------------------------------------------------------------------------+
|                     FLASK APPLICATION BACKEND                            |
|                                                                          |
|  1. Validate User Session & File Constraints (Max 25MB)                  |
|  2. Generate 16-byte Random Salt                                         |
|  3. Key Derivation: PBKDF2-HMAC-SHA256(MasterKey + UserID, Salt, 100k)  |
|  4. Generate 96-bit Random Nonce (IV)                                    |
|  5. AES-256-GCM Authenticated Encryption:                                |
|     Plaintext ------> [AES-256-GCM] ------> Ciphertext + 16-byte Tag     |
+--------------------------------------------------------------------------+
             /                                            \
            v                                              v
+-----------------------------+             +------------------------------+
|       SQLITE DATABASE       |             |       STORAGE ADAPTER        |
|  - User Credentials (Hash)  |             |                              |
|  - File Metadata:           |             |  [Local Vault] or [AWS S3]   |
|    * Nonce (Hex)            |             |                              |
|    * Auth Tag (Hex)         |             |  Stores:                     |
|    * Salt (Hex)             |             |  Raw Encrypted Ciphertext    |
|    * Storage Key URI        |             |  (Zero Plaintext on Disk)    |
+-----------------------------+             +------------------------------+
```

---

## 3. Technology Stack

- **Backend Framework:** Python 3.11, Flask 3.0.3, Werkzeug 3.0.3
- **Cryptography:** Python `cryptography` 42.0.7 (AESGCM, PBKDF2HMAC, SHA256)
- **Database:** SQLite 3 with Parameterized SQL (Zero SQLi risk)
- **Cloud Storage:** Amazon S3 SDK (`boto3` 1.34) + Local Filesystem Adapter
- **Testing:** `pytest` 8.2.1
- **UI:** Modern Responsive Dashboard (HTML5, Bootstrap 5 / Tailwind CSS, JetBrains Mono)

---

## 4. Windows PowerShell Setup & Run

### Step 1: Open Windows PowerShell in the project directory
```powershell
cd secure-cloud-storage
```

### Step 2: Run Automated PowerShell Script
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\run_windows.ps1
```

### Manual Step-by-Step Commands (PowerShell):
```powershell
# 1. Verify Python 3.11+ is installed
python --version

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 4. Install dependencies
pip install -r requirements.txt

# 5. Create .env configuration
Copy-Item .env.example .env

# 6. Run automated tests
pytest -v

# 7. Start Flask server
python app.py
```

Open your web browser and navigate to: **`http://127.0.0.1:5000`**

---

## 5. Amazon S3 Configuration

To connect the application to Amazon S3:

1. Create a private S3 bucket in your AWS Console (e.g. `my-secure-encrypted-college-vault`).
2. Ensure **Block Public Access** is set to **ON**.
3. Create an IAM User with the following least-privilege policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::my-secure-encrypted-college-vault/*"
    }
  ]
}
```
4. Update `.env`:
```ini
STORAGE_BACKEND=s3
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
S3_BUCKET_NAME=my-secure-encrypted-college-vault
```

---

## 6. Running Test Suites

Run all unit and integration tests with pytest:
```powershell
pytest -v
```

Test coverage includes:
1. `test_aes_gcm_encryption_roundtrip`: Verifies bidirectional data accuracy.
2. `test_empty_file_encryption`: Zero-byte edge cases.
3. `test_binary_file_encryption`: Image/PDF byte preservation.
4. `test_unique_nonce_per_operation`: CSPRNG nonce independence.
5. `test_tampered_ciphertext_detection`: GCM tag mismatch on bit corruption.
6. `test_tampered_auth_tag_detection`: Authentication failure on tag spoofing.
7. `test_wrong_key_rejection`: Cryptographic isolation across users.
8. `test_cross_user_file_access_denied`: 403 Forbidden enforcement.

---

## 7. College Submission Document
A complete 15-section final year PBL report is available in:
`docs/COLLEGE_PBL_REPORT.md` (includes Abstract, DFDs, ER schema, Viva Q&A, and demo scripts).
