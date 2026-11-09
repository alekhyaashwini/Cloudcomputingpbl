import React, { useState, useEffect } from 'react';
import { CryptoInspectionData } from '../types';

interface CryptoInspectorModalProps {
  fileId: string | null;
  token: string | null;
  onClose: () => void;
}

export const CryptoInspectorModal: React.FC<CryptoInspectorModalProps> = ({
  fileId,
  token,
  onClose
}) => {
  const [data, setData] = useState<CryptoInspectionData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  useEffect(() => {
    if (!fileId || !token) return;

    setLoading(true);
    fetch(`/api/crypto/inspect/${fileId}`, {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => {
        if (!res.ok) throw new Error('Failed to load cryptographic inspection metadata');
        return res.json();
      })
      .then(json => {
        setData(json);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, [fileId, token]);

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  if (!fileId) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-3xl w-full p-6 shadow-2xl my-8">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <div className="text-xs font-mono text-indigo-400">Cryptographic AEAD Inspector</div>
            <h3 className="text-lg font-bold text-white mt-0.5">
              {data ? data.fileName : 'Inspecting Encrypted Object'}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        {loading && (
          <div className="py-12 text-center text-slate-400 text-sm">
            Computing cryptographic parameters and reading ciphertext...
          </div>
        )}

        {error && (
          <div className="my-6 p-4 rounded bg-red-950/40 border border-red-800 text-red-300 text-sm">
            {error}
          </div>
        )}

        {data && (
          <div className="space-y-5 mt-5 text-sm">
            {/* Tamper Warning if active */}
            {data.isTampered && (
              <div className="p-3 bg-red-950/60 border border-red-700 rounded-lg text-red-200 text-xs">
                <strong>Simulated Tamper Active:</strong> 1 byte in the ciphertext storage was flipped. AES-256-GCM authentication tag verification will reject this payload upon download!
              </div>
            )}

            {/* Cryptographic Pipeline Flow */}
            <div className="bg-slate-900/80 p-4 rounded-lg border border-slate-800">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                NIST SP 800-38D Authenticated Encryption Pipeline
              </div>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-center text-xs">
                <div className="p-2 bg-slate-800/80 rounded border border-slate-700">
                  <div className="text-slate-400 font-mono">1. Plaintext</div>
                  <div className="text-white mt-1">Raw File Stream</div>
                </div>
                <div className="p-2 bg-slate-800/80 rounded border border-slate-700">
                  <div className="text-indigo-400 font-mono">2. KDF (100k)</div>
                  <div className="text-white mt-1">PBKDF2-HMAC-SHA256</div>
                </div>
                <div className="p-2 bg-slate-800/80 rounded border border-slate-700">
                  <div className="text-emerald-400 font-mono">3. AES-256-GCM</div>
                  <div className="text-white mt-1">96-bit CSPRNG Nonce</div>
                </div>
                <div className="p-2 bg-slate-800/80 rounded border border-slate-700">
                  <div className="text-amber-400 font-mono">4. Storage</div>
                  <div className="text-white mt-1">Ciphertext + 128b Tag</div>
                </div>
              </div>
            </div>

            {/* Parameter Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              {/* Nonce (IV) */}
              <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-300">Nonce / Initialization Vector (IV)</span>
                  <span className="text-xs font-mono text-slate-400 tabular-nums">96 bits (12 bytes)</span>
                </div>
                <div className="mt-2 font-mono text-xs text-indigo-300 bg-slate-950 p-2 rounded border border-slate-800 break-all select-all flex items-center justify-between gap-2">
                  <span>{data.nonceIV.hex}</span>
                  <button
                    onClick={() => copyToClipboard(data.nonceIV.hex, 'nonce')}
                    className="text-xs text-slate-400 hover:text-white shrink-0 cursor-pointer"
                  >
                    {copiedField === 'nonce' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                  Generated via secure random CSPRNG. Never reused across encryptions with the same key.
                </p>
              </div>

              {/* Authentication Tag (MAC) */}
              <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-300">GHASH Authentication Tag</span>
                  <span className="text-xs font-mono text-slate-400 tabular-nums">128 bits (16 bytes)</span>
                </div>
                <div className="mt-2 font-mono text-xs text-amber-300 bg-slate-950 p-2 rounded border border-slate-800 break-all select-all flex items-center justify-between gap-2">
                  <span>{data.authTag.hex}</span>
                  <button
                    onClick={() => copyToClipboard(data.authTag.hex, 'tag')}
                    className="text-xs text-slate-400 hover:text-white shrink-0 cursor-pointer"
                  >
                    {copiedField === 'tag' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                  Guarantees message authenticity. Any single-bit corruption in storage triggers instant rejection.
                </p>
              </div>

              {/* Key Derivation Salt */}
              <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-300">Key Derivation Salt</span>
                  <span className="text-xs font-mono text-slate-400 tabular-nums">128 bits (16 bytes)</span>
                </div>
                <div className="mt-2 font-mono text-xs text-emerald-300 bg-slate-950 p-2 rounded border border-slate-800 break-all select-all flex items-center justify-between gap-2">
                  <span>{data.salt.hex}</span>
                  <button
                    onClick={() => copyToClipboard(data.salt.hex, 'salt')}
                    className="text-xs text-slate-400 hover:text-white shrink-0 cursor-pointer"
                  >
                    {copiedField === 'salt' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                  Prevents rainbow-table attacks. Guarantees per-file symmetric key independence.
                </p>
              </div>

              {/* Storage Backend & Key */}
              <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-300">Storage Backend & Target</span>
                  <span className="text-xs font-mono text-slate-400">{data.storageBackend.toUpperCase()}</span>
                </div>
                <div className="mt-2 font-mono text-xs text-slate-300 bg-slate-950 p-2 rounded border border-slate-800 truncate select-all flex items-center justify-between gap-2">
                  <span className="truncate">{data.storageKey}</span>
                  <button
                    onClick={() => copyToClipboard(data.storageKey, 'key')}
                    className="text-xs text-slate-400 hover:text-white shrink-0 cursor-pointer"
                  >
                    {copiedField === 'key' ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="mt-1 text-xs text-slate-500 leading-relaxed">
                  Stored as UUID-derived key to eliminate path-traversal vulnerabilities.
                </p>
              </div>

            </div>

            {/* Ciphertext Raw Hex Preview */}
            <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-slate-300">
                  Stored Ciphertext Preview (First 64 Bytes Hex Dump)
                </span>
                <span className="text-xs font-mono text-slate-400 tabular-nums">
                  Total Payload: {data.ciphertextLengthBytes} bytes
                </span>
              </div>
              <div className="font-mono text-xs bg-black/60 p-3 rounded border border-slate-800 text-slate-300 overflow-x-auto tracking-widest leading-loose">
                {data.ciphertextHexPreview.match(/.{1,2}/g)?.join(' ') || data.ciphertextHexPreview}
              </div>
              <div className="mt-2 text-xs text-slate-500">
                Notice high entropy and complete lack of plaintext patterns. No identifiable file headers or ASCII strings.
              </div>
            </div>

          </div>
        )}

        {/* Footer */}
        <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors cursor-pointer"
          >
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
};
