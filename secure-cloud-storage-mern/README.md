# Secure Cloud File Storage Using Client-Side Encryption (Zero-Knowledge Architecture)
### Final Year B.Tech CSE Project-Based Learning (PBL) Implementation
**Stack:** React.js (Vite) + Web Crypto API + Node.js/Express + MongoDB (Mongoose) + Amazon S3 / MinIO

---

## 1. System Architecture: The Zero-Knowledge Guarantee

In standard cloud storage architectures (e.g. Dropbox, Google Drive, or AWS SSE-S3), files are either encrypted on the server or the server possesses the decryption keys. An employee with internal access, a cloud provider subpoena, or a compromised database exposes the user's plaintext files.

This project implements a true **Zero-Knowledge Architecture**:
1. **Client-Side Encryption:** Plaintext files are encrypted directly in the user's browser using the **W3C Web Cryptography API** (`window.crypto.subtle`) using **AES-256-GCM** before network transmission.
2. **Key Isolation:** The user's master passphrase never leaves the browser. Symmetric 256-bit keys are derived locally in browser memory via **PBKDF2-HMAC-SHA256 (100,000 rounds)** with a unique 16-byte random salt.
3. **Zero-Knowledge Server:** The Node.js Express server, MongoDB database, and Amazon S3 / MinIO buckets **only ever receive, store, and stream encrypted ciphertext**.
4. **Integrity Verification:** During decryption, the browser re-evaluates the 128-bit GHASH authentication tag. Any tampering or bit-flipping at rest in cloud storage immediately throws an authentication error.

```
+-----------------------------------------------------------------------------------------+
|                                    USER BROWSER (REACT)                                 |
|                                                                                         |
|  1. Plaintext File Selected                                                             |
|  2. User Passphrase (NEVER sent over network)                                           |
|  3. Salt Generation: 16-byte CSPRNG                                                     |
|  4. Key Derivation: PBKDF2-HMAC-SHA256(Passphrase, Salt, 100,000 iterations)            |
|  5. Nonce Generation: 96-bit (12 bytes) CSPRNG Nonce                                    |
|  6. AES-256-GCM Authenticated Encryption:                                               |
|     Plaintext -----> [Web Crypto API] -----> Ciphertext + 16-byte Authentication Tag    |
+-----------------------------------------------------------------------------------------+
                                           |
                   POST /api/files/upload  |  (ONLY CIPHERTEXT + IV + TAG + SALT)
                                           v
+-----------------------------------------------------------------------------------------+
|                                NODE.JS + EXPRESS BACKEND                                |
|                                                                                         |
|  - Validates JWT Bearer Token                                                           |
|  - Enforces User File Ownership & Tenant Isolation                                      |
|  - Receives Ciphertext Buffer (Zero Plaintext Processed)                                |
+-----------------------------------------------------------------------------------------+
                   /                                                       \
                  v                                                         v
+-----------------------------------+                     +-------------------------------+
|         MONGODB DATABASE          |                     |     AMAZON S3 / MINIO BUCKET  |
|                                   |                     |                               |
| Stores Metadata:                  |                     | Stores Encrypted Blob:        |
| - Owner ObjectId                  |                     | - S3 Object Key               |
| - Original Name & MIME            |                     | - Pure Ciphertext Bytes       |
| - Nonce / IV (Hex)                |                     | (Completely unreadable data)  |
| - Auth Tag (Hex)                  |                     +-------------------------------+
| - PBKDF2 Salt (Hex)               |
+-----------------------------------+
```

---

## 2. Complete Project Directory Structure

```
secure-cloud-storage-mern/
├── docker-compose.yml              # Single-command setup for MongoDB + MinIO
├── README.md                       # Complete documentation & setup instructions
│
├── backend/
│   ├── package.json                # Express, Mongoose, @aws-sdk/client-s3, bcryptjs, jsonwebtoken
│   ├── .env.example                # MongoDB URI, MinIO/S3 credentials, JWT secrets
│   ├── server.js                   # Express server entry point
│   └── src/
│       ├── config/
│       │   ├── db.js               # Mongoose database connection
│       │   └── s3.js               # AWS SDK v3 S3Client (MinIO & AWS S3 adapter)
│       ├── models/
│       │   ├── User.js             # Mongoose User Schema (salted bcrypt hash)
│       │   └── File.js             # Mongoose File Schema (IV, Tag, Salt, StorageKey)
│       ├── middleware/
│       │   └── auth.js             # JWT Bearer token authentication middleware
│       └── routes/
│           ├── auth.js             # /register, /login, /me endpoints
│           └── files.js            # /upload, /download/:id, /delete/:id, /list
│
└── frontend/
    ├── package.json                # React 18, Vite, Tailwind CSS, Axios, Lucide
    ├── vite.config.ts              # Vite configuration with API proxy to port 5000
    ├── index.html                  # HTML entry point with Plus Jakarta Sans typography
    ├── .env.example                # VITE_API_URL configuration
    └── src/
        ├── services/
        │   ├── crypto.ts           # Web Cryptography API (PBKDF2 & AES-256-GCM)
        │   └── api.ts              # Axios HTTP client with JWT interceptor
        ├── components/
        │   ├── Dashboard.tsx       # File manager and storage statistics
        │   ├── UploadModal.tsx     # In-browser client-side encryption dropzone
        │   └── CryptoInspector.tsx # Raw ciphertext & GHASH tag inspector
        ├── App.tsx                 # Main React component
        └── main.tsx                # React DOM mount point
```

---

## 3. Step-by-Step Installation & Setup

### Prerequisites
- **Node.js:** v18.0.0 or higher
- **npm:** v9.0.0 or higher
- **Docker & Docker Compose:** Required to run local MongoDB and MinIO without manual installation.

---

### Step 1: Start MongoDB & MinIO with Docker
Run the following command from the root directory:
```bash
docker compose up -d
```
This spins up:
- **MongoDB:** `localhost:27017`
- **MinIO S3 Storage:** `http://localhost:9000` (API) & `http://localhost:9001` (Web Console)
- **Bucket Auto-Creator:** Automatically creates the private bucket `secure-cloud-files`.

> **MinIO Web Console Login:**
> - URL: `http://localhost:9001`
> - Username: `minioadmin`
> - Password: `minioadminpassword`

---

### Step 2: Configure & Start Backend
1. Open a terminal and navigate to `backend/`:
   ```bash
   cd backend
   ```
2. Create your `.env` file:
   ```bash
   # Windows PowerShell:
   Copy-Item .env.example .env

   # Linux / macOS:
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start development server:
   ```bash
   npm run dev
   ```
The backend will boot on **`http://localhost:5000`** and log:
`[MongoDB Connected]` and `ZERO-KNOWLEDGE CLOUD STORAGE BACKEND ACTIVE`.

---

### Step 3: Configure & Start Frontend
1. Open a second terminal and navigate to `frontend/`:
   ```bash
   cd frontend
   ```
2. Create your `.env` file:
   ```bash
   # Windows PowerShell:
   Copy-Item .env.example .env

   # Linux / macOS:
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Start Vite development server:
   ```bash
   npm run dev
   ```
The frontend will start at **`http://localhost:3000`**.

---

## 4. Switching from MinIO to Real Amazon S3

To switch to Amazon S3 in production:
1. Create a private bucket in the AWS Console (e.g. `my-university-secure-files`).
2. Attach an IAM Policy with `s3:PutObject`, `s3:GetObject`, and `s3:DeleteObject`.
3. Update `backend/.env`:
   ```ini
   STORAGE_PROVIDER=s3
   S3_BUCKET_NAME=my-university-secure-files
   S3_REGION=us-east-1
   S3_ENDPOINT=
   S3_FORCE_PATH_STYLE=false
   AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
   AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   ```
Restart the backend. The application now uses real Amazon S3 with zero code changes.

---

## 5. REST API Documentation

### Authentication Routes (`/api/auth`)
| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/auth/register` | Create account with salted bcrypt password | No |
| `POST` | `/api/auth/login` | Authenticate user & issue JWT Bearer token | No |
| `GET` | `/api/auth/me` | Fetch authenticated profile & user salt | Yes (JWT) |

### File Vault Routes (`/api/files`)
| Method | Endpoint | Description | Payload | Auth |
|---|---|---|---|---|
| `GET` | `/api/files/list` | List metadata of all files owned by user | None | Yes |
| `POST` | `/api/files/upload` | Save client-encrypted ciphertext to S3 | `{ base64Ciphertext, ivHex, authTagHex, saltHex, originalName, mimeType }` | Yes |
| `GET` | `/api/files/download/:id` | Fetch ciphertext stream for browser decryption | None | Yes |
| `DELETE` | `/api/files/:id` | Permanently delete S3 blob and MongoDB record | None | Yes |

---

## 6. Key Management & Web Cryptography API Details

### Key Derivation (PBKDF2-HMAC-SHA256)
- **Input:** User Master Passphrase + 16-byte cryptographically secure random salt.
- **Iterations:** 100,000 rounds.
- **Hash:** SHA-256.
- **Output:** 256-bit symmetric key (`CryptoKey` object marked `extractable: false` so browser extensions or malicious scripts cannot dump the raw key from memory).

### Authenticated Encryption (AES-256-GCM)
- **Nonce (IV):** 96-bit (12 bytes) pseudo-random initialization vector via `window.crypto.getRandomValues(new Uint8Array(12))`.
- **Integrity Tag:** 128-bit GHASH tag calculated automatically by WebCrypto.
- **Verification:** During `crypto.subtle.decrypt()`, if the authentication tag fails to match the ciphertext, the browser throws `OperationError`.
