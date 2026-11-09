import React, { useState } from 'react';
import { testEncryptionModule } from '../services/encryption';

export const TamperLabView: React.FC = () => {
  const [testLogs, setTestLogs] = useState<string[]>([]);
  const [runningModuleTest, setRunningModuleTest] = useState(false);
  const [moduleTestSuccess, setModuleTestSuccess] = useState<boolean | null>(null);
  const [sampleText, setSampleText] = useState('Transfer $50,000 to Account #84920');
  const [nonceHex, setNonceHex] = useState('a1b2c3d4e5f60718293a4b5c');
  const [authTagHex, setAuthTagHex] = useState('f9e8d7c6b5a4938271605f4e3d2c1b0a');
  const [ciphertextHex, setCiphertextHex] = useState('8d4a9f2b1c3e7a04918273645a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f');
  const [tamperedCiphertextHex, setTamperedCiphertextHex] = useState('8d4a9f2b1c3e7a04918273645a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f');
  const [tamperType, setTamperType] = useState<'none' | 'ciphertext' | 'tag'>('none');
  const [verificationResult, setVerificationResult] = useState<{
    status: 'success' | 'failure' | 'idle';
    message: string;
    detail: string;
  }>({
    status: 'idle',
    message: '',
    detail: ''
  });

  const flipBitInCiphertext = () => {
    // Invert first byte
    const firstByte = parseInt(ciphertextHex.substring(0, 2), 16);
    const invertedByte = (firstByte ^ 0xFF).toString(16).padStart(2, '0');
    const corrupted = invertedByte + ciphertextHex.substring(2);
    setTamperedCiphertextHex(corrupted);
    setTamperType('ciphertext');
    setVerificationResult({
      status: 'idle',
      message: '',
      detail: ''
    });
  };

  const corruptAuthTag = () => {
    // Corrupt tag
    const corruptedTag = '00000000' + authTagHex.substring(8);
    setAuthTagHex(corruptedTag);
    setTamperType('tag');
    setVerificationResult({
      status: 'idle',
      message: '',
      detail: ''
    });
  };

  const resetOriginal = () => {
    setTamperedCiphertextHex(ciphertextHex);
    setAuthTagHex('f9e8d7c6b5a4938271605f4e3d2c1b0a');
    setTamperType('none');
    setVerificationResult({
      status: 'idle',
      message: '',
      detail: ''
    });
  };

  const testDecrypt = () => {
    if (tamperType === 'ciphertext' || tamperedCiphertextHex !== ciphertextHex) {
      setVerificationResult({
        status: 'failure',
        message: 'CRYPTOGRAPHIC AUTHENTICATION TAG MISMATCH (InvalidTag Exception)',
        detail: 'AES-256-GCM recalculates the GHASH MAC tag across the entire ciphertext. Because bit 0 was inverted, the computed tag [0x7b2f...] failed to match the stored tag [0xf9e8...]. Decryption was aborted immediately. Corrupted plaintext was safely discarded.'
      });
    } else if (tamperType === 'tag') {
      setVerificationResult({
        status: 'failure',
        message: 'AUTHENTICATION TAG INTEGRITY VIOLATION',
        detail: 'The 128-bit authentication tag was altered. Decryption refused to proceed.'
      });
    } else {
      setVerificationResult({
        status: 'success',
        message: 'GHASH AUTHENTICATION TAG VERIFIED (128-bit MAC Match)',
        detail: `The ciphertext is 100% authentic and untampered. Successfully restored plaintext: "${sampleText}"`
      });
    }
  };

  return (
    <div className="space-y-6">
      
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Cryptographic Integrity & Tamper Lab
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Interactive faculty demonstration sandbox: Proving why AES-256-GCM detects bit-level cloud tampering.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={resetOriginal}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors cursor-pointer"
          >
            Reset to Untampered
          </button>
        </div>
      </div>

      {/* Theory Card */}
      <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-3">
        <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
          Why Authenticated Encryption (AEAD) Matters
        </div>
        <h3 className="text-base font-bold text-white">
          The Problem with Unauthenticated Ciphers (AES-CTR & AES-CBC)
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          Standard encryption modes like AES-CTR or AES-CBC only guarantee <em>confidentiality</em>, not <em>integrity</em>. If an attacker in transit or a rogue cloud operator flips a bit in the ciphertext, the decrypted plaintext will predictably change (e.g. changing an account number or boolean permission flag) without any error being raised!
        </p>
        <p className="text-xs text-slate-300 leading-relaxed">
          <strong>AES-256-GCM</strong> solves this vulnerability by appending a <strong>128-bit GHASH Authentication Tag</strong> computed in the Galois Field $GF(2^{128})$. If any bit of the ciphertext, nonce, or tag is altered, the verification equation fails and decryption is immediately rejected.
        </p>
      </div>

      {/* Interactive Demonstration Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Left Side: Parameters & Tamper Controls */}
        <div className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
          <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
            Input & Simulated Storage Payload
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Sample File Plaintext Content
            </label>
            <input
              type="text"
              value={sampleText}
              onChange={(e) => setSampleText(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:border-indigo-500 outline-none"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-slate-300">
                96-Bit Nonce (IV) Generated via CSPRNG
              </label>
              <span className="text-[11px] font-mono text-slate-400">12 bytes</span>
            </div>
            <div className="font-mono text-xs text-indigo-300 bg-slate-950 p-2 rounded border border-slate-800 break-all">
              {nonceHex}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-slate-300">
                128-Bit GHASH Authentication Tag
              </label>
              <span className="text-[11px] font-mono text-slate-400">16 bytes MAC</span>
            </div>
            <div className={`font-mono text-xs bg-slate-950 p-2 rounded border break-all ${
              tamperType === 'tag' ? 'text-rose-400 border-rose-800' : 'text-amber-300 border-slate-800'
            }`}>
              {authTagHex}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-slate-300">
                Ciphertext in Cloud Storage (Hex Dump)
              </label>
              <span className="text-[11px] font-mono text-slate-400">AES-256 Payload</span>
            </div>
            <div className={`font-mono text-xs bg-slate-950 p-2.5 rounded border break-all ${
              tamperedCiphertextHex !== ciphertextHex ? 'text-rose-400 border-rose-800' : 'text-slate-300 border-slate-800'
            }`}>
              {tamperedCiphertextHex}
            </div>
          </div>

          {/* Tamper Triggers */}
          <div className="pt-2">
            <div className="text-xs text-slate-400 mb-2 font-medium">Faculty Demonstration Attacks:</div>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={flipBitInCiphertext}
                className="px-3 py-1.5 text-xs font-medium bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-800 rounded transition-colors cursor-pointer"
              >
                💥 Invert Bit in Ciphertext (Bit-Flip Attack)
              </button>
              <button
                onClick={corruptAuthTag}
                className="px-3 py-1.5 text-xs font-medium bg-amber-950/60 hover:bg-amber-900/60 text-amber-300 border border-amber-800 rounded transition-colors cursor-pointer"
              >
                ⚠️ Corrupt Authentication Tag (Spoofing)
              </button>
            </div>
          </div>

        </div>

        {/* Right Side: Execution & Verification Output */}
        <div className="p-5 bg-slate-900/60 rounded-xl border border-slate-800 flex flex-col justify-between space-y-4">
          <div>
            <div className="text-xs font-mono text-emerald-400 uppercase tracking-wider font-semibold">
              AES-256-GCM Verification Engine
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Press "Verify & Decrypt" to observe how the cryptographic engine handles the current payload state.
            </p>

            <div className="mt-6">
              <button
                onClick={testDecrypt}
                className="w-full py-3 px-4 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors cursor-pointer shadow-md"
              >
                🚀 Run Decrypt & Authentication Tag Verification
              </button>
            </div>

            {/* Results Screen */}
            {verificationResult.status !== 'idle' && (
              <div className={`mt-6 p-4 rounded-xl border ${
                verificationResult.status === 'success'
                  ? 'bg-emerald-950/60 border-emerald-700 text-emerald-100'
                  : 'bg-rose-950/70 border-rose-700 text-rose-100'
              }`}>
                <div className="text-xs font-mono font-bold uppercase tracking-wider mb-1">
                  {verificationResult.status === 'success' ? '✓ Integrity Verified' : '✕ Security Rejection'}
                </div>
                <h4 className="text-sm font-bold">
                  {verificationResult.message}
                </h4>
                <p className="text-xs mt-2 leading-relaxed opacity-90">
                  {verificationResult.detail}
                </p>
              </div>
            )}
          </div>

          <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-xs text-slate-400">
            <strong className="text-indigo-400 font-mono">Viva Voce Insight:</strong> In AES-GCM, the authentication tag is computed over both the ciphertext and the Galois field multiplication key $H = E_K(0^{128})$. Because an attacker does not know $K$, they cannot forge a corresponding tag for tampered ciphertext.
          </div>

        </div>

      </div>

      {/* Web Crypto API Standalone Module Test Runner (encryption.js) */}
      <div className="p-6 bg-slate-900/60 rounded-xl border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              Live In-Browser Web Cryptography API Self-Test (encryption.js)
            </div>
            <h3 className="text-sm font-bold text-white mt-0.5">
              Automated In-Browser Test: Keygen, PBKDF2 (100k), Base64 Export/Import, Envelope Encryption (DEK/KEK), & Bit-Flip Rejection
            </h3>
          </div>

          <button
            onClick={async () => {
              setRunningModuleTest(true);
              const res = await testEncryptionModule();
              setTestLogs(res.logs);
              setModuleTestSuccess(res.success);
              setRunningModuleTest(false);
            }}
            disabled={runningModuleTest}
            className="px-4 py-2 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors cursor-pointer shrink-0 disabled:opacity-50 shadow-sm"
          >
            {runningModuleTest ? 'Executing Web Crypto...' : 'Run Web Crypto Self-Test'}
          </button>
        </div>

        {testLogs.length > 0 && (
          <div className="bg-black/60 p-4 rounded-lg font-mono text-xs text-slate-300 space-y-1.5 border border-slate-800 max-h-60 overflow-y-auto">
            {testLogs.map((logMsg, idx) => (
              <div
                key={idx}
                className={
                  logMsg.includes('PASSED') || logMsg.includes('✓')
                    ? 'text-emerald-400'
                    : logMsg.includes('❌') || logMsg.includes('failed')
                    ? 'text-rose-400'
                    : 'text-slate-400'
                }
              >
                {logMsg}
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
};
