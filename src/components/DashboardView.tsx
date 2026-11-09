import React, { useState, useRef } from 'react';
import { StoredFile, UserProfile, StorageConfig } from '../types';
import { clientEncryptFile, clientDecryptFile, bufferToHex, hexToUint8Array } from '../services/webCrypto';

interface DashboardViewProps {
  files: StoredFile[];
  user: UserProfile;
  token: string;
  storageConfig: StorageConfig;
  onRefreshFiles: () => void;
  onInspectCrypto: (fileId: string) => void;
  onOpenStorageConfig: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  files,
  user,
  token,
  storageConfig,
  onRefreshFiles,
  onInspectCrypto,
  onOpenStorageConfig
}) => {
  const [encryptionMode, setEncryptionMode] = useState<'client-zk' | 'server'>('client-zk');
  const [masterPassphrase, setMasterPassphrase] = useState('PBL_ZeroKnowledge_MasterSecret_2026!');
  const [uploading, setUploading] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [tamperingId, setTamperingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [tamperAlert, setTamperAlert] = useState<{ fileName: string; message: string; detail: string } | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Compute metrics
  const totalOriginalBytes = files.reduce((acc, f) => acc + f.originalSize, 0);
  const totalEncryptedBytes = files.reduce((acc, f) => acc + f.encryptedSize, 0);

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  };

  const handleFileUpload = async (file: File) => {
    if (file.size > 25 * 1024 * 1024) {
      setUploadError('File exceeds maximum allowable limit of 25MB for this PBL demonstration.');
      return;
    }

    setUploading(true);
    setUploadError(null);

    try {
      if (encryptionMode === 'client-zk') {
        // ============================================================
        // 1. CLIENT-SIDE ZERO-KNOWLEDGE ENCRYPTION (Web Crypto API)
        // Encrypts in browser before transmission! Plaintext never leaves browser!
        // ============================================================
        const buffer = await file.arrayBuffer();
        const encryptedResult = await clientEncryptFile(buffer, masterPassphrase);

        // Convert ciphertext buffer to base64 for JSON transmission
        const binary = String.fromCharCode(...new Uint8Array(encryptedResult.ciphertextBuffer));
        const base64Ciphertext = window.btoa(binary);

        const res = await fetch('/api/files/upload-client-encrypted', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`
          },
          body: JSON.stringify({
            fileName: file.name,
            mimeType: file.type || 'application/octet-stream',
            originalSize: file.size,
            base64Ciphertext,
            ivHex: encryptedResult.ivHex,
            authTagHex: encryptedResult.authTagHex,
            saltHex: encryptedResult.saltHex
          })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        onRefreshFiles();
        setUploading(false);
      } else {
        // ============================================================
        // 2. SERVER-SIDE ENCRYPTION (Fallback / Comparative mode)
        // ============================================================
        const reader = new FileReader();
        reader.onload = async () => {
          const base64Data = (reader.result as string).split(',')[1];
          const res = await fetch('/api/files/upload', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`
            },
            body: JSON.stringify({
              fileName: file.name,
              mimeType: file.type || 'application/octet-stream',
              base64Data
            })
          });

          const data = await res.json();
          if (!res.ok) {
            throw new Error(data.error || 'Failed to encrypt and store file');
          }

          onRefreshFiles();
          setUploading(false);
        };
        reader.readAsDataURL(file);
      }
    } catch (err: any) {
      setUploadError(err.message);
      setUploading(false);
    }
  };

  const handleDownload = async (file: StoredFile) => {
    setDownloadingId(file.id);
    setTamperAlert(null);

    try {
      if (file.keyId.includes('client-webcrypto')) {
        // ============================================================
        // 1. CLIENT-SIDE ZERO-KNOWLEDGE DECRYPTION (Web Crypto API)
        // Fetch raw ciphertext, then decrypt locally inside browser!
        // ============================================================
        const res = await fetch(`/api/files/download-raw/${file.id}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);

        // Convert base64 ciphertext to ArrayBuffer
        const binaryString = window.atob(data.base64Ciphertext);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }

        try {
          const decryptedBuffer = await clientDecryptFile(
            bytes.buffer,
            masterPassphrase,
            file.saltHex,
            file.ivHex
          );

          const blob = new Blob([decryptedBuffer], { type: file.mimeType });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = file.originalName;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        } catch (decryptErr: any) {
          setTamperAlert({
            fileName: file.originalName,
            message: 'CLIENT-SIDE AUTHENTICATION TAG MISMATCH (Web Crypto OperationError)',
            detail: 'The ciphertext retrieved from cloud storage failed GHASH tag verification or was decrypted with an incorrect master passphrase. Plaintext was safely discarded to protect your system.'
          });
        }
      } else {
        // ============================================================
        // 2. SERVER-SIDE DECRYPTION
        // ============================================================
        const res = await fetch(`/api/files/download/${file.id}`, {
          headers: { Authorization: `Bearer ${token}` }
        });

        const data = await res.json();

        if (!res.ok) {
          if (data.tampered) {
            setTamperAlert({
              fileName: file.originalName,
              message: data.error,
              detail: data.detail
            });
            return;
          }
          throw new Error(data.error || 'Failed to decrypt file');
        }

        const binaryString = window.atob(data.base64Data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: data.mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = data.fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      setUploadError(`Download/Decryption failed: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleTamperToggle = async (file: StoredFile) => {
    setTamperingId(file.id);
    const endpoint = file.isTampered ? `/api/files/restore/${file.id}` : `/api/files/tamper/${file.id}`;

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error);
      }
      onRefreshFiles();
    } catch (err: any) {
      setUploadError(err.message);
    } finally {
      setTamperingId(null);
    }
  };

  const handleDelete = async (fileId: string) => {
    if (!confirm('Are you sure you want to delete this encrypted object from cloud storage?')) return;
    setDeletingId(fileId);

    try {
      const res = await fetch(`/api/files/${fileId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error);
      }
      onRefreshFiles();
    } catch (err: any) {
      setUploadError(err.message);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Top Banner / Welcome Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Encrypted Cloud Storage Dashboard
          </h1>
          <div className="text-xs text-slate-400 mt-1 flex items-center gap-2">
            <span>User: <strong className="text-slate-200">{user.username}</strong></span>
            <span aria-hidden="true">·</span>
            <span>Session: <strong className="text-slate-200 font-mono">Authenticated (PBKDF2)</strong></span>
            <span aria-hidden="true">·</span>
            <span>Zero Plaintext at Rest</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onOpenStorageConfig}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <span>Storage Adapter:</span>
            <strong className="text-indigo-400 font-mono uppercase">{storageConfig.backend}</strong>
          </button>
        </div>
      </div>

      {/* Critical Security Tamper Alert if triggered */}
      {tamperAlert && (
        <div className="p-4 bg-red-950/80 border border-red-700 rounded-xl text-red-100 animate-fadeIn">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <div className="text-xs font-mono uppercase tracking-wider text-red-400 font-bold">
                ⚠️ Cryptographic Integrity Violation Detected (Requirement #5)
              </div>
              <h4 className="text-sm font-bold text-white">
                {tamperAlert.message}
              </h4>
              <p className="text-xs text-red-200 leading-relaxed mt-1">
                Target File: <strong>{tamperAlert.fileName}</strong>. {tamperAlert.detail}
              </p>
            </div>
            <button
              onClick={() => setTamperAlert(null)}
              className="text-red-400 hover:text-white text-xs px-2 py-1 rounded bg-red-900/40 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Statistics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Stored Encrypted Files</div>
          <div className="text-2xl font-bold text-white mt-1 font-mono tabular-nums">
            {files.length}
          </div>
          <div className="text-xs text-slate-500 mt-1">Tenant isolated objects</div>
        </div>

        <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Decrypted Original Size</div>
          <div className="text-2xl font-bold text-indigo-400 mt-1 font-mono tabular-nums">
            {formatBytes(totalOriginalBytes)}
          </div>
          <div className="text-xs text-slate-500 mt-1">Plaintext data volume</div>
        </div>

        <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Encrypted Vault Storage</div>
          <div className="text-2xl font-bold text-amber-400 mt-1 font-mono tabular-nums">
            {formatBytes(totalEncryptedBytes)}
          </div>
          <div className="text-xs text-slate-500 mt-1">Ciphertext + MAC tags</div>
        </div>

        <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800">
          <div className="text-xs text-slate-400 font-medium">Cipher Suite Standard</div>
          <div className="text-lg font-bold text-emerald-400 mt-1 font-mono truncate">
            AES-256-GCM
          </div>
          <div className="text-xs text-slate-500 mt-1">96b Nonce · 128b Tag</div>
        </div>

      </div>

      {/* Upload Dropzone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragActive(false);
          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileUpload(e.dataTransfer.files[0]);
          }
        }}
        className={`p-6 rounded-xl border-2 border-dashed transition-all text-center ${
          dragActive
            ? 'border-indigo-500 bg-indigo-950/20'
            : 'border-slate-800 bg-slate-900/30 hover:border-slate-700'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileUpload(e.target.files[0]);
            }
          }}
        />

        <div className="max-w-md mx-auto space-y-3">
          <div className="w-12 h-12 rounded-full bg-indigo-600/20 border border-indigo-500/30 mx-auto flex items-center justify-center text-indigo-400 text-xl font-bold">
            🛡️
          </div>

          <div>
            <h3 className="text-sm font-semibold text-white">
              Encrypt & Upload New File to Cloud Vault
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Drag and drop any file here (PDF, image, document, binary) or click to browse. Max 25MB.
            </p>
          </div>

          {/* Zero-Knowledge Mode Switcher */}
          <div className="bg-slate-950/80 p-3 rounded-lg border border-slate-800 text-left space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Encryption Architecture:</span>
              <div className="flex gap-1.5">
                <button
                  type="button"
                  onClick={() => setEncryptionMode('client-zk')}
                  className={`px-2.5 py-1 text-xs font-semibold rounded transition-colors cursor-pointer ${
                    encryptionMode === 'client-zk'
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  Client Zero-Knowledge (Web Crypto)
                </button>
                <button
                  type="button"
                  onClick={() => setEncryptionMode('server')}
                  className={`px-2.5 py-1 text-xs font-semibold rounded transition-colors cursor-pointer ${
                    encryptionMode === 'server'
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  Server-Side
                </button>
              </div>
            </div>

            {encryptionMode === 'client-zk' && (
              <div className="pt-2 border-t border-slate-800/80">
                <label className="block text-[11px] font-medium text-indigo-300 mb-1">
                  Client Master Passphrase (Web Crypto PBKDF2 — Never leaves this browser):
                </label>
                <input
                  type="password"
                  value={masterPassphrase}
                  onChange={(e) => setMasterPassphrase(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white font-mono outline-none focus:border-indigo-500"
                  placeholder="Master passphrase for in-browser AES-256-GCM derivation"
                />
              </div>
            )}
          </div>

          {uploadError && (
            <div className="text-xs text-red-400 font-medium bg-red-950/50 p-2 rounded border border-red-900">
              {uploadError}
            </div>
          )}

          <div>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="px-5 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors cursor-pointer disabled:opacity-50 shadow-sm"
            >
              {uploading
                ? encryptionMode === 'client-zk'
                  ? 'Encrypting in Browser via Web Crypto API...'
                  : 'Deriving Key & Encrypting...'
                : `Select File to Encrypt (${encryptionMode === 'client-zk' ? 'Zero-Knowledge' : 'Server'})`}
            </button>
          </div>

          <div className="text-xs text-slate-500 font-mono">
            {encryptionMode === 'client-zk'
              ? 'Web Crypto API: Plaintext & passphrase stay 100% inside your browser.'
              : 'Server-Side: AES-256-GCM computed on backend with isolated user keys.'}
          </div>
        </div>
      </div>

      {/* Uploaded Files Table */}
      <div className="bg-slate-900/50 rounded-xl border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Encrypted Files in Cloud Vault</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Only authenticated owner ({user.username}) can decrypt these objects.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400 tabular-nums">
            {files.length} {files.length === 1 ? 'object' : 'objects'}
          </span>
        </div>

        {files.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No encrypted files in your vault yet. Upload your first file above to observe AES-256-GCM in action.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-medium bg-slate-900/80">
                  <th className="py-3 px-4">File Name & Mime</th>
                  <th className="py-3 px-4">Original Size</th>
                  <th className="py-3 px-4">Encrypted Size</th>
                  <th className="py-3 px-4">Nonce (IV) / Tag</th>
                  <th className="py-3 px-4">Integrity Status</th>
                  <th className="py-3 px-4 text-right">Cryptographic Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {files.map((file) => (
                  <tr key={file.id} className="hover:bg-slate-800/30 transition-colors">
                    
                    {/* File Name */}
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white truncate max-w-xs" title={file.originalName}>
                        {file.originalName}
                      </div>
                      <div className="text-slate-500 text-[11px] font-mono mt-0.5">
                        {file.mimeType} · {file.storageBackend.toUpperCase()}
                      </div>
                    </td>

                    {/* Original Size */}
                    <td className="py-3 px-4 font-mono text-slate-300 tabular-nums">
                      {formatBytes(file.originalSize)}
                    </td>

                    {/* Encrypted Size */}
                    <td className="py-3 px-4 font-mono text-amber-300 tabular-nums">
                      {formatBytes(file.encryptedSize)}
                    </td>

                    {/* Nonce / Tag */}
                    <td className="py-3 px-4 font-mono text-[11px]">
                      <div className="text-indigo-400">
                        IV: {file.ivHex.substring(0, 10)}...
                      </div>
                      <div className="text-amber-400">
                        Tag: {file.authTagHex.substring(0, 10)}...
                      </div>
                    </td>

                    {/* Integrity Status */}
                    <td className="py-3 px-4">
                      {file.isTampered ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-rose-400 font-medium bg-rose-950/50 px-2 py-0.5 rounded border border-rose-800">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
                          Tampered (Bit-Flipped)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-medium bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                          Untampered (Valid Tag)
                        </span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        
                        {/* Inspect Crypto */}
                        <button
                          onClick={() => onInspectCrypto(file.id)}
                          className="px-2.5 py-1 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors cursor-pointer"
                          title="Inspect raw ciphertext hex, IV, Tag, and KDF details"
                        >
                          Inspect
                        </button>

                        {/* Download & Decrypt */}
                        <button
                          onClick={() => handleDownload(file)}
                          disabled={downloadingId === file.id}
                          className="px-2.5 py-1 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded transition-colors cursor-pointer disabled:opacity-50"
                          title="Decrypt with AES-256-GCM and verify MAC tag"
                        >
                          {downloadingId === file.id ? 'Verifying...' : 'Decrypt & Get'}
                        </button>

                        {/* Tamper Simulation Toggle */}
                        <button
                          onClick={() => handleTamperToggle(file)}
                          disabled={tamperingId === file.id}
                          className={`px-2 py-1 text-xs font-medium rounded transition-colors cursor-pointer ${
                            file.isTampered
                              ? 'bg-amber-900/60 hover:bg-amber-800 text-amber-200 border border-amber-700'
                              : 'bg-slate-800 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-700'
                          }`}
                          title="Simulate 1-byte ciphertext corruption to prove AEAD rejection"
                        >
                          {file.isTampered ? 'Restore' : 'Corrupt 1 Byte'}
                        </button>

                        {/* Delete */}
                        <button
                          onClick={() => handleDelete(file.id)}
                          disabled={deletingId === file.id}
                          className="px-2 py-1 text-xs text-slate-400 hover:text-rose-400 hover:bg-slate-800 rounded transition-colors cursor-pointer"
                          title="Delete from storage and database"
                        >
                          ✕
                        </button>

                      </div>
                    </td>

                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

      </div>

    </div>
  );
};
