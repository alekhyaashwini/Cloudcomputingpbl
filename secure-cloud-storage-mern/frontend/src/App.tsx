import React, { useState, useEffect } from 'react';
import api from './services/api';
import { encryptFileClientSide, decryptFileClientSide } from './services/crypto';

interface FileRecord {
  _id: string;
  originalName: string;
  mimeType: string;
  originalSize: number;
  encryptedSize: number;
  ivHex: string;
  authTagHex: string;
  saltHex: string;
  createdAt: string;
}

export default function App() {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [user, setUser] = useState<{ id: string; username: string; email: string } | null>(null);
  const [passphrase, setPassphrase] = useState('MyZeroKnowledgeSecretPassphrase2026!');
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [uploading, setUploading] = useState(false);
  const [decryptingId, setDecryptingId] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  // Load files
  const loadFiles = async () => {
    try {
      const res = await api.get('/files/list');
      setFiles(res.data.files || []);
    } catch (err: any) {
      console.error(err);
    }
  };

  useEffect(() => {
    if (token) {
      loadFiles();
    }
  }, [token]);

  // Client-Side Zero-Knowledge Upload
  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    try {
      // 1. Read file buffer in browser
      const buffer = await file.arrayBuffer();

      // 2. Encrypt locally in browser using Web Crypto API
      const encrypted = await encryptFileClientSide(buffer, passphrase);

      // 3. Send ONLY ciphertext to backend Express server
      await api.post('/files/upload', {
        originalName: file.name,
        mimeType: file.type || 'application/octet-stream',
        originalSize: file.size,
        base64Ciphertext: encrypted.base64Ciphertext,
        ivHex: encrypted.ivHex,
        authTagHex: encrypted.authTagHex,
        saltHex: encrypted.saltHex
      });

      await loadFiles();
    } catch (err: any) {
      alert(`Encryption/Upload failed: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  // Client-Side Zero-Knowledge Download & Decrypt
  const handleDownloadAndDecrypt = async (file: FileRecord) => {
    setDecryptingId(file._id);
    try {
      // 1. Retrieve raw ciphertext from server
      const res = await api.get(`/files/download/${file._id}`);
      const { base64Ciphertext, ivHex, saltHex } = res.data;

      // 2. Decrypt locally in browser using Web Crypto API
      const decryptedBuffer = await decryptFileClientSide(
        base64Ciphertext,
        passphrase,
        saltHex,
        ivHex
      );

      // 3. Save decrypted file to disk
      const blob = new Blob([decryptedBuffer], { type: file.mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.originalName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Decryption failed: ${err.message}`);
    } finally {
      setDecryptingId(null);
    }
  };

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <header className="flex justify-between items-center pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white">Client-Side Zero-Knowledge Vault</h1>
          <p className="text-xs text-slate-400 mt-1">
            Files are encrypted in your browser using the Web Crypto API before reaching Express & MinIO/S3.
          </p>
        </div>
      </header>

      {/* Passphrase Card */}
      <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 space-y-2">
        <label className="text-xs font-semibold text-indigo-400 uppercase">
          Client-Side Master Passphrase (Zero-Knowledge: Never sent to server)
        </label>
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs font-mono text-white outline-none"
        />
        <div className="text-[11px] text-slate-500">
          Used to derive 256-bit AES-GCM keys via PBKDF2 (100,000 rounds) strictly inside this browser instance.
        </div>
      </div>

      {/* Upload Zone */}
      <div className="bg-slate-900/60 p-6 rounded-xl border border-dashed border-slate-800 text-center space-y-3">
        <input
          type="file"
          id="file-input"
          className="hidden"
          onChange={handleUpload}
          disabled={uploading}
        />
        <label
          htmlFor="file-input"
          className="inline-block px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-lg cursor-pointer transition-colors"
        >
          {uploading ? 'Encrypting in Browser & Uploading...' : 'Select File to Encrypt & Store'}
        </label>
      </div>

      {/* Files Table */}
      <div className="bg-slate-900/50 rounded-xl border border-slate-800 overflow-hidden">
        <table className="w-full text-xs text-left">
          <thead className="bg-slate-950 text-slate-400 font-semibold border-b border-slate-800">
            <tr>
              <th className="p-3">File Name</th>
              <th className="p-3">Original Size</th>
              <th className="p-3">Ciphertext Size</th>
              <th className="p-3">Nonce (IV)</th>
              <th className="p-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {files.map((file) => (
              <tr key={file._id} className="hover:bg-slate-800/40">
                <td className="p-3 font-medium text-white">{file.originalName}</td>
                <td className="p-3 text-slate-400 font-mono">{(file.originalSize / 1024).toFixed(1)} KB</td>
                <td className="p-3 text-amber-300 font-mono">{(file.encryptedSize / 1024).toFixed(1)} KB</td>
                <td className="p-3 text-indigo-400 font-mono">{file.ivHex.slice(0, 10)}...</td>
                <td className="p-3 text-right">
                  <button
                    onClick={() => handleDownloadAndDecrypt(file)}
                    disabled={decryptingId === file._id}
                    className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-semibold cursor-pointer disabled:opacity-50"
                  >
                    {decryptingId === file._id ? 'Decrypting...' : 'Decrypt & Download'}
                  </button>
                </td>
              </tr>
            ))}
            {files.length === 0 && (
              <tr>
                <td colSpan={5} className="p-6 text-center text-slate-500">
                  No encrypted files stored.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
