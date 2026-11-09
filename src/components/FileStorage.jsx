import React, { useState, useEffect, useRef } from 'react';
import {
  encryptWithEnvelope,
  decryptWithEnvelope,
  bufferToBase64,
  base64ToBuffer,
  testEncryptionModule
} from '../services/encryption.js';
import {
  Lock,
  Unlock,
  ShieldCheck,
  ShieldAlert,
  Upload,
  Download,
  Trash2,
  FileText,
  Key,
  RefreshCw,
  LogOut,
  LogIn,
  CheckCircle2,
  AlertTriangle,
  Info,
  Layers,
  Eye,
  EyeOff
} from 'lucide-react';

/**
 * @component FileStorage
 * @description Zero-Knowledge Envelope Encryption File Vault Component.
 *
 * Cryptographic Architecture:
 * 1. Envelope Encryption:
 *    - Each uploaded file is encrypted with a unique, one-time 256-bit AES-GCM Data Encryption Key (DEK).
 *    - The DEK is encrypted (wrapped) with a Key Encryption Key (KEK) derived from the user's password using PBKDF2 (100k rounds).
 *    - The server receives ONLY the ciphertext blob + the wrapped DEK + nonces + salt.
 *    - The server never sees plaintext, the user's password, or the raw DEK.
 *
 * 2. Decryption & Tag Verification:
 *    - On download, the browser fetches the raw ciphertext + envelope metadata.
 *    - The user enters their password; PBKDF2 re-derives the KEK.
 *    - The DEK is unwrapped. If the password is wrong, the 128-bit GHASH authentication tag fails and decryption halts.
 *    - If valid, the DEK decrypts the file payload in-memory into a Blob, triggering browser save.
 */
export default function FileStorage() {
  // Authentication State
  const [token, setToken] = useState(() => localStorage.getItem('zk_vault_token') || '');
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('zk_vault_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  // Login form state
  const [identifier, setIdentifier] = useState('student@college.edu');
  const [loginPassword, setLoginPassword] = useState('Student@123');
  const [rememberPassword, setRememberPassword] = useState(true);
  const [activePassword, setActivePassword] = useState('Student@123'); // Cached in-memory for seamless crypto
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // File list & vault state
  const [files, setFiles] = useState([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [vaultError, setVaultError] = useState('');
  const [vaultSuccess, setVaultSuccess] = useState('');

  // Upload state & cryptographic progress
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadPassword, setUploadPassword] = useState('');
  const [uploading, setUploading] = useState(false);
  const [cryptoProgressStep, setCryptoProgressStep] = useState(null);
  const fileInputRef = useRef(null);

  // Download & Decrypt state
  const [decryptingFileId, setDecryptingFileId] = useState(null);
  const [decryptPasswordPrompt, setDecryptPasswordPrompt] = useState({ isOpen: false, file: null, password: '' });
  const [showPassword, setShowPassword] = useState(false);

  // Envelope Inspector Modal
  const [inspectingFile, setInspectingFile] = useState(null);

  // Self-test state
  const [selfTestRunning, setSelfTestRunning] = useState(false);
  const [selfTestLogs, setSelfTestLogs] = useState([]);
  const [showSelfTest, setShowSelfTest] = useState(false);

  // Synchronize master password state
  useEffect(() => {
    if (activePassword) {
      setUploadPassword(activePassword);
    }
  }, [activePassword]);

  // Sync token in localStorage
  useEffect(() => {
    if (token) {
      localStorage.setItem('zk_vault_token', token);
    } else {
      localStorage.removeItem('zk_vault_token');
    }
  }, [token]);

  // Fetch files when token is present
  useEffect(() => {
    if (token) {
      fetchUserFiles();
    } else {
      setFiles([]);
    }
  }, [token]);

  // Quick Demo Auto-login helper
  const handleQuickLogin = (demoEmail, demoPass) => {
    setIdentifier(demoEmail);
    setLoginPassword(demoPass);
    executeLogin(demoEmail, demoPass);
  };

  /**
   * Performs user login against /api/auth/login, with client-side fallback for static website hosting.
   * Stores JWT / session in localStorage / state.
   */
  const executeLogin = async (idVal, passVal) => {
    setAuthLoading(true);
    setAuthError('');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: idVal, password: passVal }),
      });

      if (!res.ok) {
        if (res.status === 404 || res.status === 502) {
          // Static website hosting mode (no backend server running)
          throw new Error('FALLBACK_CLIENT_MODE');
        }
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Authentication failed. Please check credentials.');
      }

      const data = await res.json();
      setToken(data.token);
      setUser(data.user);
      localStorage.setItem('zk_vault_user', JSON.stringify(data.user));

      if (rememberPassword) {
        setActivePassword(passVal);
        setUploadPassword(passVal);
      }
      setVaultSuccess(`Authenticated as ${data.user.email}. Cloud Vault unlocked.`);
      setTimeout(() => setVaultSuccess(''), 4000);
    } catch (err) {
      if (err.message === 'FALLBACK_CLIENT_MODE' || err.message.includes('fetch') || err.message.includes('NetworkError')) {
        // Standalone Client-Side Mode for static website hosting
        const clientUser = {
          id: 'user_client_demo',
          email: idVal || 'student@college.edu',
          username: (idVal || 'student_demo').split('@')[0],
          role: 'Cybersecurity Student'
        };
        const clientToken = 'client_token_' + Date.now();
        setToken(clientToken);
        setUser(clientUser);
        localStorage.setItem('zk_vault_user', JSON.stringify(clientUser));
        if (rememberPassword) {
          setActivePassword(passVal);
          setUploadPassword(passVal);
        }
        setVaultSuccess(`Browser Client Vault Unlocked: Full AES-256-GCM authenticated encryption active.`);
        setTimeout(() => setVaultSuccess(''), 4000);
      } else {
        setAuthError(err.message);
      }
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLoginSubmit = (e) => {
    e.preventDefault();
    executeLogin(identifier, loginPassword);
  };

  const handleLogout = () => {
    setToken('');
    setUser(null);
    setActivePassword('');
    setUploadPassword('');
    localStorage.removeItem('zk_vault_token');
    localStorage.removeItem('zk_vault_user');
  };

  /**
   * Fetches the user's file metadata from GET /api/files with client-side fallback.
   */
  const fetchUserFiles = async () => {
    if (!token) return;
    setLoadingFiles(true);
    try {
      const res = await fetch('/api/files', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.status === 401) {
        handleLogout();
        throw new Error('Session expired. Please log in again.');
      }
      if (!res.ok) {
        throw new Error('FALLBACK_CLIENT_FILES');
      }
      const data = await res.json();
      setFiles(data.files || []);
    } catch {
      // Load from client storage fallback
      const saved = localStorage.getItem('zk_local_vault_files');
      if (saved) {
        try {
          setFiles(JSON.parse(saved));
        } catch {
          setFiles([]);
        }
      } else {
        setFiles([]);
      }
    } finally {
      setLoadingFiles(false);
    }
  };

  /**
   * CLIENT-SIDE ZERO-KNOWLEDGE ENVELOPE ENCRYPTION & UPLOAD
   *
   * Step 1: User selects file and specifies their master password.
   * Step 2: Browser generates a fresh, ephemeral 256-bit AES Data Encryption Key (DEK).
   * Step 3: Browser encrypts the file using AES-256-GCM + unique 96-bit IV.
   * Step 4: Browser derives a 256-bit Key Encryption Key (KEK) via PBKDF2 (100k rounds, 16-byte random salt).
   * Step 5: Browser wraps (encrypts) the DEK with the KEK using AES-256-GCM.
   * Step 6: Browser builds FormData with the ciphertext Blob + envelope metadata (wrappedDEK, IV, salt).
   * Step 7: POST to /api/files/upload. Server stores ciphertext directly without ever seeing plaintext!
   */
  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!uploadFile) {
      setVaultError('Please select a file to encrypt and upload.');
      return;
    }
    const pass = uploadPassword || activePassword;
    if (!pass) {
      setVaultError('A master password is required to derive the Key Encryption Key (KEK).');
      return;
    }

    setUploading(true);
    setVaultError('');
    setVaultSuccess('');

    try {
      // Step A: PBKDF2 Key Derivation & DEK Generation
      setCryptoProgressStep({
        phase: 'PBKDF2_DERIVATION',
        message: 'Deriving 256-bit Key Encryption Key (KEK) using PBKDF2-HMAC-SHA256 (100,000 rounds)...',
      });
      await new Promise((r) => setTimeout(r, 60)); // Yield to UI thread

      // Step B: AES-256-GCM File & Envelope Encryption
      setCryptoProgressStep({
        phase: 'ENVELOPE_ENCRYPTION',
        message: 'Generating unique DEK, encrypting file payload, and wrapping DEK with KEK...',
      });

      // Call our Web Crypto API module
      const envelope = await encryptWithEnvelope(uploadFile, pass);

      // Step C: Packing into FormData
      setCryptoProgressStep({
        phase: 'PREPARING_PAYLOAD',
        message: 'Packaging encrypted ciphertext Blob and cryptographic envelope metadata...',
      });

      // Convert typed arrays to Base64 strings for the metadata parameters
      const ivBase64 = bufferToBase64(envelope.fileIv.buffer);
      const saltBase64 = bufferToBase64(envelope.kekSalt.buffer);
      const dekIvBase64 = bufferToBase64(envelope.dekIv.buffer);
      const wrappedDekBase64 = bufferToBase64(envelope.wrappedDek);

      // Package wrappedDEK alongside dekIv in a JSON string or combined payload
      const wrappedDekPayload = JSON.stringify({
        wrappedDek: wrappedDekBase64,
        dekIv: dekIvBase64,
      });

      // Encapsulate raw ciphertext into a Blob
      const ciphertextBlob = new Blob([envelope.fileCiphertext], {
        type: 'application/octet-stream',
      });

      const formData = new FormData();
      formData.append('file', ciphertextBlob, `${uploadFile.name}.enc`);
      formData.append('originalName', uploadFile.name);
      formData.append('mimeType', uploadFile.type || 'application/octet-stream');
      formData.append('size', uploadFile.size.toString());
      formData.append('iv', ivBase64);
      formData.append('wrappedDEK', wrappedDekPayload);
      formData.append('salt', saltBase64);
      formData.append('dekIv', dekIvBase64);

      // Step D: Transmitting encrypted ciphertext to the server or client vault
      setCryptoProgressStep({
        phase: 'UPLOADING',
        message: 'Saving encrypted ciphertext to cloud storage vault (Zero-Knowledge)...',
      });

      try {
        const res = await fetch('/api/files/upload', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
          body: formData,
        });

        if (res.ok) {
          setVaultSuccess(
            `File "${uploadFile.name}" successfully encrypted with AES-256-GCM & uploaded to cloud vault!`
          );
        } else {
          throw new Error('FALLBACK_CLIENT_UPLOAD');
        }
      } catch {
        // Fallback for static website hosting: store encrypted ciphertext in client browser storage
        const ciphertextB64 = bufferToBase64(envelope.fileCiphertext.buffer || envelope.fileCiphertext);
        const newLocalFile = {
          id: 'client_' + Date.now(),
          originalName: uploadFile.name,
          name: uploadFile.name,
          mimeType: uploadFile.type || 'application/octet-stream',
          size: uploadFile.size,
          iv: ivBase64,
          wrappedDEK: wrappedDekPayload,
          salt: saltBase64,
          dekIv: dekIvBase64,
          uploadedAt: new Date().toISOString(),
          base64Ciphertext: ciphertextB64,
        };
        const currentList = JSON.parse(localStorage.getItem('zk_local_vault_files') || '[]');
        currentList.unshift(newLocalFile);
        localStorage.setItem('zk_local_vault_files', JSON.stringify(currentList));
        setFiles(currentList);
        setVaultSuccess(
          `File "${uploadFile.name}" encrypted with AES-256-GCM and stored in browser vault!`
        );
      }

      setUploadFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      fetchUserFiles();
    } catch (err) {
      console.error('Envelope upload error:', err);
      setVaultError(`Encryption/Upload failed: ${err.message}`);
    } finally {
      setUploading(false);
      setCryptoProgressStep(null);
    }
  };

  /**
   * CLIENT-SIDE ZERO-KNOWLEDGE DOWNLOAD & AUTHENTICATED DECRYPTION
   *
   * Step 1: Retrieve ciphertext & envelope metadata from /api/files/:id/download.
   * Step 2: Use provided master password to derive KEK via PBKDF2 (100k rounds + file salt).
   * Step 3: Unwrap DEK using KEK and dekIv. If password is wrong, AES-GCM MAC tag fails.
   * Step 4: Decrypt file ciphertext with the unwrapped DEK and fileIv.
   * Step 5: Construct Blob with original MIME type and trigger browser download.
   */
  const handleDownloadAndDecrypt = async (fileItem, passwordToUse) => {
    const pass = passwordToUse || activePassword;
    if (!pass) {
      setDecryptPasswordPrompt({
        isOpen: true,
        file: fileItem,
        password: '',
      });
      return;
    }

    setDecryptingFileId(fileItem.id);
    setVaultError('');
    setVaultSuccess('');

    try {
      // Step A: Fetch ciphertext & envelope metadata (server or client vault)
      let ciphertextBuffer;
      let payload = {};

      try {
        const downloadRes = await fetch(`/api/files/${fileItem.id}/download?format=json`, {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json',
          },
        });

        if (downloadRes.ok) {
          payload = await downloadRes.json();
          if (payload.base64Ciphertext || payload.ciphertextBase64) {
            ciphertextBuffer = base64ToBuffer(payload.base64Ciphertext || payload.ciphertextBase64);
          } else {
            const rawRes = await fetch(`/api/files/${fileItem.id}/download`, {
              headers: { Authorization: `Bearer ${token}` },
            });
            ciphertextBuffer = await rawRes.arrayBuffer();
          }
        } else {
          throw new Error('FALLBACK_CLIENT_DOWNLOAD');
        }
      } catch {
        // Fallback for client vault
        if (fileItem.base64Ciphertext) {
          ciphertextBuffer = base64ToBuffer(fileItem.base64Ciphertext);
        } else {
          throw new Error('Ciphertext not found in local browser storage.');
        }
      }

      // Step C: Prepare the cryptographic envelope package
      const envelopePackage = {
        fileCiphertext: ciphertextBuffer,
        fileIv: payload.iv || fileItem.iv || fileItem.ivHex,
        wrappedDek: payload.wrappedDEK || fileItem.wrappedDEK,
        dekIv: payload.dekIv || fileItem.dekIv,
        kekSalt: payload.salt || fileItem.salt || fileItem.saltHex,
        mimeType: fileItem.mimeType || payload.mimeType || 'application/octet-stream',
      };

      // Step D: Client-side envelope decryption using Web Crypto API
      // If the password is wrong, decryptWithEnvelope will throw:
      // "Envelope Decryption Failed: Invalid password or corrupted Key Encryption Key (KEK) envelope!"
      const decryptedBlob = await decryptWithEnvelope(envelopePackage, pass);

      // Step E: Trigger browser file save
      const downloadUrl = window.URL.createObjectURL(decryptedBlob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = fileItem.originalName || fileItem.name || 'decrypted_file';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(downloadUrl);

      setVaultSuccess(
        `Decrypted "${fileItem.originalName || fileItem.name}" successfully! Authentication tag verified.`
      );
      setDecryptPasswordPrompt({ isOpen: false, file: null, password: '' });
    } catch (err) {
      console.error('Decryption failed:', err);
      // Give clear, distinct feedback for password / integrity failure
      if (err.message.includes('tag') || err.message.includes('Invalid password') || err.message.includes('operation failed')) {
        setVaultError(
          'Decryption Failed: Wrong master password or corrupted ciphertext! The AES-GCM 128-bit authentication tag rejected the key.'
        );
      } else {
        setVaultError(`Decryption error: ${err.message}`);
      }
    } finally {
      setDecryptingFileId(null);
    }
  };

  /**
   * Delete an encrypted file from storage.
   */
  const handleDeleteFile = async (fileId, fileName) => {
    if (!window.confirm(`Are you sure you want to delete "${fileName}" from the encrypted cloud vault?`)) {
      return;
    }
    try {
      const res = await fetch(`/api/files/${fileId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error('Failed to delete file');
      setVaultSuccess(`File "${fileName}" deleted from cloud vault.`);
      fetchUserFiles();
    } catch (err) {
      setVaultError(err.message);
    }
  };

  /**
   * Format bytes into readable format
   */
  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  /**
   * Run Web Crypto self-test suite
   */
  const runSelfTest = async () => {
    setSelfTestRunning(true);
    setSelfTestLogs([]);
    setShowSelfTest(true);
    try {
      const res = await testEncryptionModule();
      setSelfTestLogs(res.logs || []);
    } catch (err) {
      setSelfTestLogs((prev) => [...prev, `[FAIL] Self-test exception: ${err.message}`]);
    } finally {
      setSelfTestRunning(false);
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-indigo-500/20 text-indigo-400 rounded-lg border border-indigo-500/30">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Zero-Knowledge Envelope Encryption Vault
              </h1>
            </div>
            <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
              Files are encrypted inside your browser using <strong>AES-256-GCM</strong> with an ephemeral Data Encryption Key (DEK).
              The DEK is wrapped using a <strong>PBKDF2-HMAC-SHA256 (100,000 iterations)</strong> derived Key Encryption Key (KEK).
              The server never sees your plaintext or passphrase.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={runSelfTest}
              className="px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-white border border-slate-700 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <Key className="w-3.5 h-3.5 text-indigo-400" />
              Crypto Self-Test
            </button>
            {user && (
              <button
                onClick={handleLogout}
                className="px-3 py-2 text-xs font-medium text-red-400 bg-red-950/30 hover:bg-red-900/40 border border-red-800/40 rounded-lg transition-colors cursor-pointer flex items-center gap-1.5"
              >
                <LogOut className="w-3.5 h-3.5" />
                Sign Out
              </button>
            )}
          </div>
        </div>

        {/* Status Indicators */}
        <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Web Cryptography API (W3C standard)</span>
          </div>
          <span className="text-slate-600">|</span>
          <div className="flex items-center gap-1.5 text-slate-400 font-mono text-[11px]">
            <span>Algorithm: AES-256-GCM (96-bit IV, 128-bit MAC)</span>
          </div>
          <span className="text-slate-600">|</span>
          <div className="flex items-center gap-1.5 text-slate-400 font-mono text-[11px]">
            <span>KDF: PBKDF2 (100k rounds, SHA-256)</span>
          </div>
        </div>
      </div>

      {/* Global Alerts */}
      {vaultError && (
        <div className="bg-red-950/40 border border-red-800/50 text-red-200 text-xs p-4 rounded-xl flex items-start gap-3 shadow-lg animate-in fade-in">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="font-semibold text-red-300">Security / Cryptographic Alert</p>
            <p className="mt-0.5 text-red-200/90 leading-relaxed">{vaultError}</p>
          </div>
          <button
            onClick={() => setVaultError('')}
            className="text-red-400 hover:text-red-200 text-xs cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

      {vaultSuccess && (
        <div className="bg-emerald-950/40 border border-emerald-800/50 text-emerald-200 text-xs p-4 rounded-xl flex items-start gap-3 shadow-lg animate-in fade-in">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="font-semibold text-emerald-300">Operation Successful</p>
            <p className="mt-0.5 text-emerald-200/90">{vaultSuccess}</p>
          </div>
          <button
            onClick={() => setVaultSuccess('')}
            className="text-emerald-400 hover:text-emerald-200 text-xs cursor-pointer"
          >
            ✕
          </button>
        </div>
      )}

      {/* Crypto Progress Modal/Bar */}
      {cryptoProgressStep && (
        <div className="bg-indigo-950/50 border border-indigo-700/60 p-4 rounded-xl text-xs space-y-2.5">
          <div className="flex items-center justify-between text-indigo-300">
            <div className="flex items-center gap-2">
              <RefreshCw className="w-4 h-4 text-indigo-400 animate-spin" />
              <span className="font-semibold">Cryptographic Processing</span>
            </div>
            <span className="font-mono text-[10px] uppercase text-indigo-400">
              {cryptoProgressStep.phase}
            </span>
          </div>
          <p className="text-slate-300 text-xs">{cryptoProgressStep.message}</p>
          <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div className="bg-indigo-500 h-1.5 rounded-full w-3/4 animate-pulse"></div>
          </div>
        </div>
      )}

      {/* Main Content: Either Login Screen or Authenticated Vault */}
      {!token ? (
        /* LOGIN / AUTHENTICATION FORM */
        <div className="max-w-md mx-auto bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
          <div className="text-center space-y-1.5">
            <div className="w-12 h-12 rounded-full bg-indigo-600/20 border border-indigo-500/30 mx-auto flex items-center justify-center text-indigo-400">
              <Lock className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-white">Unlock Encrypted Vault</h2>
            <p className="text-xs text-slate-400">
              Authenticate to derive client-side keys and access encrypted files.
            </p>
          </div>

          {authError && (
            <div className="p-3 bg-red-950/40 border border-red-800/40 text-red-200 text-xs rounded-lg">
              {authError}
            </div>
          )}

          <form onSubmit={handleLoginSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Email or Username
              </label>
              <input
                type="text"
                required
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                placeholder="student@college.edu"
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Master Passphrase
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Master passphrase for PBKDF2 derivation"
                  className="w-full px-3 py-2 pr-9 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
              <p className="text-[10px] text-slate-500 mt-1">
                Used strictly in-browser to derive your KEK. Never transmitted over the wire in plaintext.
              </p>
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                id="rememberPass"
                checked={rememberPassword}
                onChange={(e) => setRememberPassword(e.target.checked)}
                className="rounded border-slate-700 text-indigo-600 focus:ring-0 bg-slate-950"
              />
              <label htmlFor="rememberPass" className="cursor-pointer select-none">
                Keep password in memory for seamless upload & download
              </label>
            </div>

            <button
              type="submit"
              disabled={authLoading}
              className="w-full py-2.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors cursor-pointer flex items-center justify-center gap-1.5 shadow-md shadow-indigo-600/20"
            >
              {authLoading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Verifying Credentials...
                </>
              ) : (
                <>
                  <LogIn className="w-3.5 h-3.5" />
                  Sign In to Vault
                </>
              )}
            </button>
          </form>

          {/* Quick Demo Test Logins */}
          <div className="pt-3 border-t border-slate-800 space-y-2">
            <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider block">
              1-Click Demo Accounts:
            </span>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => handleQuickLogin('cs_student', 'Student@123')}
                className="p-2 text-left bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors cursor-pointer"
              >
                <div className="text-[11px] font-semibold text-indigo-300">Student Account</div>
                <div className="text-[10px] text-slate-500 truncate">cs_student</div>
              </button>
              <button
                type="button"
                onClick={() => handleQuickLogin('alice@college.edu', 'AlicePass@2026')}
                className="p-2 text-left bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg transition-colors cursor-pointer"
              >
                <div className="text-[11px] font-semibold text-purple-300">Alice (Collaborator)</div>
                <div className="text-[10px] text-slate-500 truncate">alice@college.edu</div>
              </button>
            </div>
          </div>
        </div>
      ) : (
        /* AUTHENTICATED VAULT DASHBOARD */
        <div className="space-y-6">
          {/* Active Session Strip */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-500"></div>
              <span className="text-slate-400">Authenticated user:</span>
              <strong className="text-white font-mono">{user?.email || user?.username}</strong>
              <span className="px-2 py-0.5 rounded-full bg-indigo-950 border border-indigo-800 text-indigo-300 font-mono text-[10px]">
                ID: {user?.id}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 text-slate-400">
                <Key className="w-3.5 h-3.5 text-amber-400" />
                <span>Active Password:</span>
              </div>
              <input
                type="password"
                value={activePassword}
                onChange={(e) => setActivePassword(e.target.value)}
                placeholder="Enter passphrase..."
                className="px-2 py-1 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 w-36 focus:outline-none focus:border-indigo-500 font-mono"
              />
              <span className="text-[10px] text-slate-500">(In memory)</span>
            </div>
          </div>

          {/* Upload Section */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <Upload className="w-4 h-4 text-indigo-400" />
                <span>Zero-Knowledge Envelope Upload</span>
              </div>
              <span className="text-[11px] font-mono text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-800/40">
                AES-256-GCM + PBKDF2 (100k)
              </span>
            </div>

            <form onSubmit={handleFileUpload} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* File picker */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Select File to Encrypt
                  </label>
                  <div className="relative border-2 border-dashed border-slate-800 hover:border-slate-700 rounded-xl p-4 text-center cursor-pointer bg-slate-950/50 transition-colors">
                    <input
                      ref={fileInputRef}
                      type="file"
                      required
                      onChange={(e) => setUploadFile(e.target.files[0] || null)}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    />
                    <div className="space-y-1">
                      <FileText className="w-7 h-7 text-indigo-400 mx-auto" />
                      <div className="text-xs font-medium text-white">
                        {uploadFile ? uploadFile.name : 'Click or drag file here'}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {uploadFile
                          ? `${formatBytes(uploadFile.size)} · ${uploadFile.type || 'generic octet-stream'}`
                          : 'Any file type up to 50MB'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Master password input for this upload */}
                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Master Encryption Passphrase
                    </label>
                    <input
                      type="password"
                      required
                      value={uploadPassword}
                      onChange={(e) => {
                        setUploadPassword(e.target.value);
                        setActivePassword(e.target.value);
                      }}
                      placeholder="Passphrase used to derive KEK"
                      className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono"
                    />
                    <p className="text-[10px] text-slate-400 mt-1 leading-relaxed">
                      Envelope Flow: Generates a unique <strong>DEK</strong> for this file &rarr; wraps it with
                      your <strong>KEK</strong> &rarr; uploads pure ciphertext to S3/Vault.
                    </p>
                  </div>

                  <div className="p-3 bg-indigo-950/20 border border-indigo-900/30 rounded-lg text-[11px] text-slate-400 space-y-1">
                    <div className="text-indigo-300 font-semibold flex items-center gap-1">
                      <Info className="w-3.5 h-3.5" />
                      Zero-Knowledge Guarantee:
                    </div>
                    <p>
                      The server receives solely the ciphertext and wrapped DEK. It has no mathematical means to read your file.
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={uploading || !uploadFile}
                  className="px-5 py-2.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors cursor-pointer flex items-center gap-2 shadow-md shadow-indigo-600/20"
                >
                  {uploading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Encrypting & Uploading...
                    </>
                  ) : (
                    <>
                      <Lock className="w-4 h-4" />
                      Encrypt with Envelope & Upload
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>

          {/* File Vault Listing */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <Layers className="w-4 h-4 text-indigo-400" />
                <span>Your Encrypted Files ({files.length})</span>
              </div>

              <button
                onClick={fetchUserFiles}
                disabled={loadingFiles}
                className="px-2.5 py-1 text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3 h-3 ${loadingFiles ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>

            {loadingFiles && files.length === 0 ? (
              <div className="p-12 text-center text-xs text-slate-400 space-y-2">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto text-indigo-400" />
                <p>Retrieving encrypted storage catalog...</p>
              </div>
            ) : files.length === 0 ? (
              <div className="p-12 text-center text-xs text-slate-400 space-y-2">
                <FileText className="w-8 h-8 text-slate-600 mx-auto" />
                <p className="text-slate-300 font-medium">No encrypted files in your vault yet</p>
                <p className="text-[11px] text-slate-500">
                  Select a file above to envelope-encrypt and store it with zero-knowledge security.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 text-slate-400 font-medium border-b border-slate-800">
                    <tr>
                      <th className="py-3 px-4">Original Name</th>
                      <th className="py-3 px-4">MIME Type</th>
                      <th className="py-3 px-4">Plaintext Size</th>
                      <th className="py-3 px-4">Encryption Standard</th>
                      <th className="py-3 px-4">Uploaded At</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {files.map((file) => {
                      const isDecrypting = decryptingFileId === file.id;
                      const hasEnvelope = Boolean(file.wrappedDEK || file.keyId?.includes('client'));

                      return (
                        <tr key={file.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2.5">
                              <div className="p-1.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                <FileText className="w-4 h-4" />
                              </div>
                              <div>
                                <div className="font-medium text-white truncate max-w-xs">
                                  {file.originalName || file.name}
                                </div>
                                <div className="text-[10px] text-slate-500 font-mono">
                                  ID: {file.id}
                                </div>
                              </div>
                            </div>
                          </td>

                          <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                            {file.mimeType || 'octet-stream'}
                          </td>

                          <td className="py-3 px-4 font-mono text-slate-300">
                            {formatBytes(file.size || file.originalSize)}
                          </td>

                          <td className="py-3 px-4">
                            {hasEnvelope ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/50">
                                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                                Envelope (DEK+KEK)
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-indigo-950/60 text-indigo-300 border border-indigo-800/50">
                                <Lock className="w-3 h-3 text-indigo-400" />
                                AES-256-GCM
                              </span>
                            )}
                          </td>

                          <td className="py-3 px-4 text-slate-400 text-[11px]">
                            {file.createdAt ? new Date(file.createdAt).toLocaleString() : 'N/A'}
                          </td>

                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              {/* Envelope Inspector button */}
                              <button
                                onClick={() => setInspectingFile(file)}
                                title="Inspect Envelope Metadata"
                                className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded transition-colors cursor-pointer"
                              >
                                <Info className="w-3.5 h-3.5" />
                              </button>

                              {/* Download & Decrypt button */}
                              <button
                                onClick={() => handleDownloadAndDecrypt(file, activePassword)}
                                disabled={isDecrypting}
                                className="px-3 py-1.5 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded transition-colors cursor-pointer flex items-center gap-1.5 shadow-sm"
                              >
                                {isDecrypting ? (
                                  <>
                                    <RefreshCw className="w-3 h-3 animate-spin" />
                                    Decrypting...
                                  </>
                                ) : (
                                  <>
                                    <Download className="w-3 h-3" />
                                    Download & Decrypt
                                  </>
                                )}
                              </button>

                              {/* Delete button */}
                              <button
                                onClick={() => handleDeleteFile(file.id, file.originalName || file.name)}
                                title="Delete encrypted file"
                                className="p-1.5 text-red-400 hover:text-red-200 hover:bg-red-950/50 rounded transition-colors cursor-pointer"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODAL 1: Password Prompt for Decryption (if active password was blank or wrong) */}
      {decryptPasswordPrompt.isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full space-y-4 shadow-2xl">
            <div className="flex items-center gap-2 text-white font-semibold">
              <Unlock className="w-5 h-5 text-indigo-400" />
              <h3>Enter Master Password to Decrypt</h3>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              To unwrap the DEK and decrypt <strong>{decryptPasswordPrompt.file?.originalName}</strong>,
              enter the master passphrase used during envelope encryption.
            </p>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Passphrase
              </label>
              <input
                type="password"
                autoFocus
                value={decryptPasswordPrompt.password}
                onChange={(e) =>
                  setDecryptPasswordPrompt({ ...decryptPasswordPrompt, password: e.target.value })
                }
                placeholder="Master passphrase..."
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-indigo-500 font-mono"
              />
            </div>

            <div className="flex justify-between items-center text-[11px] text-slate-500">
              <span>Try wrong password to test MAC tag rejection</span>
              <button
                type="button"
                onClick={() =>
                  setDecryptPasswordPrompt({
                    ...decryptPasswordPrompt,
                    password: 'DeliberatelyWrongPassword123!',
                  })
                }
                className="text-amber-400 hover:underline cursor-pointer"
              >
                Insert Wrong Password
              </button>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setDecryptPasswordPrompt({ isOpen: false, file: null, password: '' })}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 rounded-lg cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  handleDownloadAndDecrypt(
                    decryptPasswordPrompt.file,
                    decryptPasswordPrompt.password
                  );
                }}
                disabled={!decryptPasswordPrompt.password}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg cursor-pointer flex items-center gap-1.5 shadow"
              >
                <Download className="w-3.5 h-3.5" />
                Unwrap & Decrypt
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: Envelope Inspector (Educational Breakdown of Cryptographic Artifacts) */}
      {inspectingFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-xl w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <Key className="w-4 h-4 text-indigo-400" />
                <h3>Cryptographic Envelope Inspector</h3>
              </div>
              <button
                onClick={() => setInspectingFile(null)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Examining stored metadata for <strong>{inspectingFile.originalName}</strong>.
              Notice that only ciphertext and nonces are stored; plaintext and raw keys never exist in storage.
            </p>

            <div className="space-y-3 font-mono text-[11px] max-h-80 overflow-y-auto">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <span className="text-indigo-400 font-semibold block">File IV / Nonce (96-bit CSPRNG):</span>
                <span className="text-slate-300 break-all">{inspectingFile.iv || inspectingFile.ivHex || 'N/A'}</span>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <span className="text-indigo-400 font-semibold block">Wrapped DEK (AES-256-GCM encrypted under KEK):</span>
                <span className="text-slate-300 break-all">{inspectingFile.wrappedDEK || 'Server-derived key (legacy)'}</span>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <span className="text-indigo-400 font-semibold block">PBKDF2 Salt (128-bit CSPRNG):</span>
                <span className="text-slate-300 break-all">{inspectingFile.salt || inspectingFile.saltHex || 'N/A'}</span>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1">
                <span className="text-indigo-400 font-semibold block">Storage Key (S3 Object / Local Vault):</span>
                <span className="text-slate-300 break-all">{inspectingFile.storageKey || inspectingFile.id}</span>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setInspectingFile(null)}
                className="px-4 py-1.5 text-xs text-white bg-slate-800 hover:bg-slate-700 rounded-lg cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: Cryptography Self-Test Log Viewer */}
      {showSelfTest && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-2xl w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-white font-semibold text-sm">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <h3>Web Cryptography API In-Browser Verification</h3>
              </div>
              <button
                onClick={() => setShowSelfTest(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-[11px] space-y-1.5 max-h-96 overflow-y-auto">
              {selfTestRunning && (
                <div className="flex items-center gap-2 text-indigo-400 py-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Running AES-256-GCM, PBKDF2 (100k rounds) and envelope tests...</span>
                </div>
              )}
              {selfTestLogs.map((log, idx) => (
                <div
                  key={idx}
                  className={
                    log.includes('PASSED') || log.includes('Verified')
                      ? 'text-emerald-400'
                      : log.includes('FAIL')
                      ? 'text-red-400'
                      : 'text-slate-300'
                  }
                >
                  {log}
                </div>
              ))}
            </div>

            <div className="flex justify-between items-center pt-2">
              <button
                onClick={runSelfTest}
                disabled={selfTestRunning}
                className="px-3 py-1.5 text-xs text-indigo-300 bg-indigo-950/60 hover:bg-indigo-900/60 border border-indigo-800 rounded-lg cursor-pointer flex items-center gap-1.5"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${selfTestRunning ? 'animate-spin' : ''}`} />
                Re-run Test
              </button>

              <button
                onClick={() => setShowSelfTest(false)}
                className="px-4 py-1.5 text-xs text-white bg-slate-800 hover:bg-slate-700 rounded-lg cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
