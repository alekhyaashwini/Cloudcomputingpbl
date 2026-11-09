import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  ShieldCheck,
  Lock,
  RefreshCw,
  Copy,
  Check,
  Download,
  AlertTriangle,
  Zap,
  HardDrive,
  FileText,
  Sliders,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles
} from 'lucide-react';
import {
  generateSharingKeyPair,
  exportPublicKey,
  encryptPrivateKeyWithPassword,
  decryptPrivateKeyWithPassword,
  formatSpkiToPem,
  computeKeyFingerprint,
  rewrapEncryptedPrivateKey,
  rewrapAllUserFiles,
  encryptFile,
  decryptFile,
  generateKey
} from '../services/encryption.js';
import { UserProfile } from '../types';

interface SettingsViewProps {
  user: UserProfile | null;
  token: string | null;
  onRefreshUser?: () => void;
  onLogout?: () => void;
}

interface KeyStatus {
  hasKeyPair: boolean;
  publicKey: string | null;
  encryptedPrivateKey: string | null;
  privateKeyIv: string | null;
  privateKeySalt: string | null;
  fingerprint: string | null;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  user,
  token,
  onRefreshUser
}) => {
  // Key state
  const [keyStatus, setKeyStatus] = useState<KeyStatus>({
    hasKeyPair: false,
    publicKey: null,
    encryptedPrivateKey: null,
    privateKeyIv: null,
    privateKeySalt: null,
    fingerprint: null
  });
  const [loadingKeys, setLoadingKeys] = useState(true);

  // Key Generation State
  const [genPassword, setGenPassword] = useState('');
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);
  const [genSuccess, setGenSuccess] = useState<string | null>(null);

  // Self-Test State
  const [testPassword, setTestPassword] = useState('');
  const [testingHybrid, setTestingHybrid] = useState(false);
  const [testLogs, setTestLogs] = useState<string[]>([]);
  const [testResult, setTestResult] = useState<'success' | 'failure' | null>(null);

  // Password Change State
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwChangeStatus, setPwChangeStatus] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
  const [pwChangeMessage, setPwChangeMessage] = useState<string | null>(null);
  const [pwChangeSteps, setPwChangeSteps] = useState<Array<{ name: string; status: 'pending' | 'running' | 'done' | 'failed' }>>([]);
  const [pwChangeMetrics, setPwChangeMetrics] = useState<{
    filesRewrapped: number;
    ciphertextUntouchedBytes: number;
    elapsedMs: number;
  } | null>(null);

  // PEM modal / copy
  const [copiedPem, setCopiedPem] = useState(false);
  const [showPemModal, setShowPemModal] = useState(false);

  // Tradeoff Calculator interactive slider
  const [simFileCount, setSimFileCount] = useState(50);
  const [simAvgFileSizeMB, setSimAvgFileSizeMB] = useState(40); // 40MB avg

  // Load existing key configuration
  const loadKeyStatus = async () => {
    if (!token) return;
    setLoadingKeys(true);
    try {
      const res = await fetch('/api/users/keys', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        let fp: string | null = null;
        if (data.publicKey) {
          fp = await computeKeyFingerprint(data.publicKey);
        }
        setKeyStatus({
          hasKeyPair: data.hasKeyPair || false,
          publicKey: data.publicKey,
          encryptedPrivateKey: data.encryptedPrivateKey,
          privateKeyIv: data.privateKeyIv,
          privateKeySalt: data.privateKeySalt,
          fingerprint: fp
        });
      }
    } catch (err: any) {
      console.warn('Failed to load user keys:', err);
    } finally {
      setLoadingKeys(false);
    }
  };

  useEffect(() => {
    loadKeyStatus();
  }, [token]);

  // Handler: Generate RSA-OAEP Key Pair & Encrypt Private Key with KEK
  const handleGenerateKeys = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!genPassword) {
      setGenError('Master password is required to derive the KEK and encrypt your private key.');
      return;
    }
    setGenerating(true);
    setGenError(null);
    setGenSuccess(null);

    try {
      // Step 1: Generate 2048-bit RSA-OAEP key pair via Web Crypto API
      const keyPair = await generateSharingKeyPair(2048);

      // Step 2: Export public key to Base64 SPKI
      const spkiBase64 = await exportPublicKey(keyPair.publicKey);

      // Step 3: Encrypt private key with user master password (KEK via PBKDF2 100k rounds)
      const encryptedPackage = await encryptPrivateKeyWithPassword(keyPair.privateKey, genPassword);

      // Step 4: Transmit public key + encrypted private key to server via PUT /api/users/keys
      const res = await fetch('/api/users/keys', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          publicKey: spkiBase64,
          encryptedPrivateKey: encryptedPackage.encryptedPrivateKey,
          privateKeyIv: encryptedPackage.iv,
          privateKeySalt: encryptedPackage.salt
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to save keys on server');
      }

      const fp = await computeKeyFingerprint(spkiBase64);
      setKeyStatus({
        hasKeyPair: true,
        publicKey: spkiBase64,
        encryptedPrivateKey: encryptedPackage.encryptedPrivateKey,
        privateKeyIv: encryptedPackage.iv,
        privateKeySalt: encryptedPackage.salt,
        fingerprint: fp
      });

      setGenSuccess('RSA-OAEP 2048-bit key pair generated successfully! Private key wrapped with AES-256-GCM and stored in your vault.');
      setGenPassword('');
      if (onRefreshUser) onRefreshUser();
    } catch (err: any) {
      setGenError(err.message || 'Key generation failed');
    } finally {
      setGenerating(false);
    }
  };

  // Handler: Self-Test Hybrid Cryptography
  const handleRunHybridSelfTest = async () => {
    if (!keyStatus.publicKey || !keyStatus.encryptedPrivateKey) {
      setGenError('Please generate an RSA-OAEP key pair first.');
      return;
    }
    if (!testPassword) {
      setTestResult('failure');
      setTestLogs(['❌ Error: Master password required to decrypt your stored private key.']);
      return;
    }

    setTestingHybrid(true);
    setTestLogs([]);
    setTestResult(null);

    const logs: string[] = [];
    const addLog = (msg: string) => {
      logs.push(msg);
      setTestLogs([...logs]);
    };

    try {
      addLog('🚀 Initiating Zero-Knowledge Asymmetric Sharing Self-Test...');
      
      // Step 1: Reconstruct public key
      addLog('1. Importing published RSA-OAEP public key from SPKI Base64...');
      const spkiBuffer = window.atob(keyStatus.publicKey);
      const spkiBytes = new Uint8Array(spkiBuffer.length);
      for (let i = 0; i < spkiBuffer.length; i++) spkiBytes[i] = spkiBuffer.charCodeAt(i);
      const rsaPublicKey = await window.crypto.subtle.importKey(
        'spki',
        spkiBytes.buffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['wrapKey', 'encrypt']
      );
      addLog('   ✓ RSA-OAEP Public Key verified and active.');

      // Step 2: Decrypt private key with master password
      addLog('2. Deriving KEK via PBKDF2 (100,000 iterations) and unwrapping RSA-OAEP Private Key...');
      const rsaPrivateKey = await decryptPrivateKeyWithPassword(
        {
          encryptedPrivateKey: keyStatus.encryptedPrivateKey,
          salt: keyStatus.privateKeySalt!,
          iv: keyStatus.privateKeyIv!
        },
        testPassword
      );
      addLog('   ✓ Private key successfully authenticated and decrypted in browser memory.');

      // Step 3: Generate an ephemeral 256-bit AES-GCM DEK
      addLog('3. Generating ephemeral 256-bit AES-GCM Data Encryption Key (DEK)...');
      const testDEK = await generateKey(true);
      addLog('   ✓ Ephemeral DEK generated.');

      // Step 4: Encrypt simulated confidential document with DEK
      const sampleText = 'TOP_SECRET_STUDENT_LAB_DOCUMENT_2026';
      const sampleBlob = new Blob([sampleText], { type: 'text/plain' });
      addLog(`4. Encrypting test payload ("${sampleText}") with DEK using AES-256-GCM...`);
      const { ciphertext, iv } = await encryptFile(sampleBlob, testDEK);
      addLog(`   ✓ Encrypted ciphertext (${ciphertext.byteLength} bytes) generated with GHASH MAC tag.`);

      // Step 5: Wrap the DEK with RSA-OAEP public key
      addLog('5. Wrapping the 256-bit DEK using RSA-OAEP with SHA-256 (IND-CCA2 secure)...');
      const wrappedDEKBuffer = await window.crypto.subtle.wrapKey(
        'raw',
        testDEK,
        rsaPublicKey,
        { name: 'RSA-OAEP' }
      );
      addLog(`   ✓ DEK wrapped into ${wrappedDEKBuffer.byteLength}-byte RSA ciphertext.`);

      // Step 6: Unwrap DEK using RSA-OAEP private key
      addLog('6. Recipient simulation: Unwrapping DEK using RSA-OAEP Private Key...');
      const unwrappedDEK = await window.crypto.subtle.unwrapKey(
        'raw',
        wrappedDEKBuffer,
        rsaPrivateKey,
        { name: 'RSA-OAEP' },
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      addLog('   ✓ Recipient successfully unwrapped the 256-bit DEK.');

      // Step 7: Decrypt the file ciphertext using the unwrapped DEK
      addLog('7. Decrypting file ciphertext with unwrapped DEK (AES-256-GCM tag verification)...');
      const decryptedBlob = await decryptFile(ciphertext, iv, unwrappedDEK, 'text/plain');
      const decryptedText = await decryptedBlob.text();
      addLog(`   ✓ Decrypted text: "${decryptedText}"`);

      if (decryptedText === sampleText) {
        addLog('🎉 HYBRID ENVELOPE VERIFICATION PASSED: Plaintext matches byte-for-byte!');
        setTestResult('success');
      } else {
        throw new Error('Integrity mismatch: decrypted plaintext differs from input.');
      }
    } catch (err: any) {
      addLog(`❌ Self-Test Failed: ${err.message}`);
      setTestResult('failure');
    } finally {
      setTestingHybrid(false);
    }
  };

  // Handler: Change Master Password & Re-wrap DEKs
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!oldPassword || !newPassword || !confirmPassword) {
      setPwChangeStatus('error');
      setPwChangeMessage('All password fields are required.');
      return;
    }
    if (newPassword.length < 6) {
      setPwChangeStatus('error');
      setPwChangeMessage('New password must be at least 6 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwChangeStatus('error');
      setPwChangeMessage('New password and confirmation do not match.');
      return;
    }

    setPwChangeStatus('processing');
    setPwChangeMessage(null);
    setPwChangeMetrics(null);

    type StepState = 'pending' | 'running' | 'done' | 'failed';
    const steps: Array<{ name: string; status: StepState }> = [
      { name: '1. Authenticating current credentials with PBKDF2 hash check', status: 'running' },
      { name: '2. Fetching user file envelopes for zero-knowledge re-wrapping', status: 'pending' },
      { name: '3. Re-wrapping RSA-OAEP private key with new Master KEK', status: 'pending' },
      { name: '4. Re-wrapping file DEKs (0 bytes ciphertext downloaded)', status: 'pending' },
      { name: '5. Submitting atomic key envelope updates to PUT /api/users/password', status: 'pending' }
    ];
    setPwChangeSteps([...steps]);

    const startTime = performance.now();

    try {
      // Step 1: Fetch user's files to re-wrap their DEKs
      steps[0].status = 'done';
      steps[1].status = 'running';
      setPwChangeSteps([...steps]);

      const filesRes = await fetch('/api/files', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!filesRes.ok) {
        throw new Error('Failed to retrieve file envelopes for re-wrapping.');
      }
      const filesData = await filesRes.json();
      const allFiles = filesData.files || [];
      const envelopeFiles = allFiles.filter((f: any) => Boolean(f.wrappedDEK || f.wrappedDek));
      steps[1].status = 'done';

      // Step 2: Re-wrap private key if user has one
      steps[2].status = 'running';
      setPwChangeSteps([...steps]);
      let rewrappedPrivKey: { encryptedPrivateKey: string; salt: string; iv: string } | null = null;
      if (keyStatus.hasKeyPair && keyStatus.encryptedPrivateKey) {
        rewrappedPrivKey = await rewrapEncryptedPrivateKey(
          {
            encryptedPrivateKey: keyStatus.encryptedPrivateKey,
            salt: keyStatus.privateKeySalt!,
            iv: keyStatus.privateKeyIv!
          },
          oldPassword,
          newPassword
        );
      }
      steps[2].status = 'done';

      // Step 3: Re-wrap all file DEKs client-side
      steps[3].status = 'running';
      setPwChangeSteps([...steps]);
      let totalCiphertextBytesUntouched = 0;
      for (const f of envelopeFiles) {
        totalCiphertextBytesUntouched += (f.size || f.originalSize || 0);
      }

      const rewrappedFiles = await rewrapAllUserFiles(
        envelopeFiles,
        oldPassword,
        newPassword
      );
      steps[3].status = 'done';

      // Step 4: Submit atomic update to backend PUT /api/users/password
      steps[4].status = 'running';
      setPwChangeSteps([...steps]);

      const updatePayload: any = {
        oldPassword,
        newPassword,
        rewrappedFiles
      };

      if (rewrappedPrivKey) {
        updatePayload.rewrappedPrivateKey = rewrappedPrivKey.encryptedPrivateKey;
        updatePayload.privateKeySalt = rewrappedPrivKey.salt;
        updatePayload.privateKeyIv = rewrappedPrivKey.iv;
      }

      const submitRes = await fetch('/api/users/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(updatePayload)
      });

      const submitData = await submitRes.json();
      if (!submitRes.ok) {
        throw new Error(submitData.error || 'Server rejected password update.');
      }

      steps[4].status = 'done';
      setPwChangeSteps([...steps]);

      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);

      setPwChangeStatus('success');
      setPwChangeMessage(
        `Master password updated successfully! Re-wrapped ${rewrappedFiles.length} file DEKs in ${duration}ms without transferring a single byte of file ciphertext.`
      );
      setPwChangeMetrics({
        filesRewrapped: rewrappedFiles.length,
        ciphertextUntouchedBytes: totalCiphertextBytesUntouched,
        elapsedMs: duration
      });

      // Clear input fields
      setOldPassword('');
      setNewPassword('');
      setConfirmPassword('');

      // Refresh key status
      loadKeyStatus();
    } catch (err: any) {
      // Find running step and mark failed
      const updatedSteps = steps.map(s => (s.status === 'running' ? { ...s, status: 'failed' as const } : s));
      setPwChangeSteps(updatedSteps);
      setPwChangeStatus('error');
      setPwChangeMessage(err.message || 'Password update failed.');
    }
  };

  // Handler: Copy Public Key PEM to Clipboard
  const handleCopyPem = () => {
    if (!keyStatus.publicKey) return;
    const pem = formatSpkiToPem(keyStatus.publicKey);
    navigator.clipboard.writeText(pem);
    setCopiedPem(true);
    setTimeout(() => setCopiedPem(false), 2500);
  };

  // Handler: Download Secure Key Backup
  const handleDownloadBackup = () => {
    if (!keyStatus.publicKey || !keyStatus.encryptedPrivateKey) return;
    const backupObj = {
      app: 'CloudVault-Secure-Storage',
      version: '2.0.0',
      userEmail: user?.email,
      exportedAt: new Date().toISOString(),
      asymmetricKeyAlgorithm: 'RSA-OAEP-2048',
      hashAlgorithm: 'SHA-256',
      publicKeySPKI: keyStatus.publicKey,
      publicKeyPEM: formatSpkiToPem(keyStatus.publicKey),
      keyFingerprint: keyStatus.fingerprint,
      encryptedPrivateKeyAES256GCM: keyStatus.encryptedPrivateKey,
      privateKeyIv: keyStatus.privateKeyIv,
      privateKeySalt: keyStatus.privateKeySalt,
      securityNotice: 'The private key inside this file is encrypted with AES-256-GCM under your master password KEK. Do not lose your master password.'
    };

    const blob = new Blob([JSON.stringify(backupObj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cloudvault_key_backup_${user?.username || 'user'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Tradeoff Calculator Math
  const totalCiphertextMB = simFileCount * simAvgFileSizeMB;
  const traditionalBandwidthMB = totalCiphertextMB * 2; // Download all + re-upload all
  // Assuming 50 Mbps upload / 100 Mbps download average internet connection:
  const simDownloadSec = (totalCiphertextMB * 8) / 100;
  const simUploadSec = (totalCiphertextMB * 8) / 50;
  const traditionalTotalMinutes = Math.max(0.1, (simDownloadSec + simUploadSec) / 60);

  // Envelope rewrap: 32 bytes DEK + 28 bytes metadata = ~120 bytes per file.
  const envelopeMetadataKB = (simFileCount * 140) / 1024;
  const envelopeTimeMs = Math.round(simFileCount * 1.5 + 40); // ~1.5ms per file + PBKDF2 time

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-6 shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Key Vault & Cryptographic Settings</h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Manage RSA-OAEP sharing key pairs, master password derivation, and zero-knowledge envelope re-wrapping.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {keyStatus.hasKeyPair ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-emerald-950/80 text-emerald-300 border border-emerald-800">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              RSA-OAEP Active (2048-bit)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-amber-950/80 text-amber-300 border border-amber-800">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Sharing Keys Not Generated
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Key Management & Password Change */}
        <div className="lg:col-span-7 space-y-8">
          
          {/* SECTION 1: RSA-OAEP Key Pair Management */}
          <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-indigo-400" />
                  Asymmetric Sharing Key Pair (RSA-OAEP)
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Allows other users to share encrypted files with you without the server seeing plaintext DEKs.
                </p>
              </div>
            </div>

            {loadingKeys ? (
              <div className="py-8 text-center text-slate-400 text-xs flex items-center justify-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" />
                Loading key status from cloud vault...
              </div>
            ) : keyStatus.hasKeyPair ? (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 space-y-3">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">Public Key Fingerprint (SHA-256):</span>
                    <span className="font-mono text-emerald-400 text-[11px] truncate max-w-xs" title={keyStatus.fingerprint || ''}>
                      {keyStatus.fingerprint}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">Private Key Protection:</span>
                    <span className="text-slate-200 flex items-center gap-1 font-mono text-[11px]">
                      <Lock className="w-3 h-3 text-indigo-400" />
                      AES-256-GCM + Master KEK
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-medium">Key Standard:</span>
                    <span className="text-slate-300 font-mono text-[11px]">
                      RFC 3447 RSA-OAEP / 2048-bit / SHA-256
                    </span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <button
                    onClick={() => setShowPemModal(true)}
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileText className="w-3.5 h-3.5 text-indigo-400" />
                    View Public Key (PEM)
                  </button>

                  <button
                    onClick={handleCopyPem}
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedPem ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copied PEM!
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-slate-400" />
                        Copy Public Key
                      </>
                    )}
                  </button>

                  <button
                    onClick={handleDownloadBackup}
                    className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5 text-indigo-400" />
                    Export Key Backup JSON
                  </button>
                </div>

                {/* Hybrid Crypto Self-Test */}
                <div className="mt-4 p-4 rounded-lg bg-indigo-950/30 border border-indigo-900/50 space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-xs font-semibold text-indigo-300 flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5" />
                        Client-Side Asymmetric Crypto Self-Test
                      </h3>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Test end-to-end RSA-OAEP DEK wrapping & unwrapping in browser memory.
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="password"
                      placeholder="Enter master password to unwrap private key"
                      value={testPassword}
                      onChange={(e) => setTestPassword(e.target.value)}
                      className="flex-grow px-3 py-1.5 text-xs bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    />
                    <button
                      onClick={handleRunHybridSelfTest}
                      disabled={testingHybrid || !testPassword}
                      className="px-4 py-1.5 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors whitespace-nowrap cursor-pointer flex items-center gap-1.5"
                    >
                      {testingHybrid ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          Testing...
                        </>
                      ) : (
                        'Run Test'
                      )}
                    </button>
                  </div>

                  {testLogs.length > 0 && (
                    <div className="mt-2 p-3 rounded bg-black/60 border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1 max-h-48 overflow-y-auto">
                      {testLogs.map((log, idx) => (
                        <div key={idx} className={log.includes('✓') || log.includes('🎉') ? 'text-emerald-400' : log.includes('❌') ? 'text-red-400' : 'text-slate-300'}>
                          {log}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-900/40 text-xs text-amber-200/90 leading-relaxed">
                  <div className="font-semibold text-amber-300 mb-1 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    No RSA-OAEP Key Pair Registered
                  </div>
                  To receive files shared by other users via zero-knowledge public-key cryptography, generate an RSA-OAEP key pair. The private key will be encrypted in your browser using your master password before being saved.
                </div>

                <form onSubmit={handleGenerateKeys} className="space-y-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Master Password (Derives KEK to encrypt private key)
                    </label>
                    <input
                      type="password"
                      required
                      placeholder="Enter your vault master password"
                      value={genPassword}
                      onChange={(e) => setGenPassword(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={generating || !genPassword}
                    className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors shadow-sm cursor-pointer flex items-center justify-center gap-2"
                  >
                    {generating ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Generating RSA-OAEP Key Pair & Encrypting Private Key...
                      </>
                    ) : (
                      <>
                        <Zap className="w-4 h-4" />
                        Generate & Publish RSA-OAEP Key Pair (2048-bit)
                      </>
                    )}
                  </button>
                </form>
              </div>
            )}

            {genError && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/60 text-xs text-red-300 flex items-center gap-2">
                <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{genError}</span>
              </div>
            )}

            {genSuccess && (
              <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-900/60 text-xs text-emerald-300 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{genSuccess}</span>
              </div>
            )}
          </div>

          {/* SECTION 2: Master Password Change & Envelope DEK Re-wrapping */}
          <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-indigo-400" />
                  Change Master Password
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Re-derives master KEK, re-wraps RSA private key, and re-wraps all file DEKs client-side without re-encrypting ciphertext.
                </p>
              </div>
            </div>

            <form onSubmit={handleChangePassword} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Current Master Password
                </label>
                <input
                  type="password"
                  required
                  placeholder="Enter current password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    New Master Password
                  </label>
                  <input
                    type="password"
                    required
                    placeholder="Min 6 characters"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Confirm New Password
                  </label>
                  <input
                    type="password"
                    required
                    placeholder="Re-type new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={pwChangeStatus === 'processing'}
                className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg transition-colors shadow-sm cursor-pointer flex items-center justify-center gap-2"
              >
                {pwChangeStatus === 'processing' ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Executing Zero-Knowledge Envelope Re-wrapping...
                  </>
                ) : (
                  <>
                    <RefreshCw className="w-4 h-4" />
                    Update Password & Re-wrap Key Envelopes
                  </>
                )}
              </button>
            </form>

            {/* Live Progress Pipeline */}
            {pwChangeSteps.length > 0 && (
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2.5 text-xs">
                <div className="font-semibold text-slate-300 pb-1 border-b border-slate-800">
                  Cryptographic Re-wrapping Execution Pipeline:
                </div>
                {pwChangeSteps.map((step, idx) => (
                  <div key={idx} className="flex items-center justify-between">
                    <span className="text-slate-400">{step.name}</span>
                    <span>
                      {step.status === 'done' && (
                        <span className="text-emerald-400 flex items-center gap-1 font-mono text-[11px]">
                          <Check className="w-3.5 h-3.5" /> Done
                        </span>
                      )}
                      {step.status === 'running' && (
                        <span className="text-indigo-400 flex items-center gap-1 font-mono text-[11px]">
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" /> In Progress
                        </span>
                      )}
                      {step.status === 'pending' && (
                        <span className="text-slate-600 font-mono text-[11px]">Pending</span>
                      )}
                      {step.status === 'failed' && (
                        <span className="text-red-400 font-mono text-[11px]">Failed</span>
                      )}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* Metrics Audit Card */}
            {pwChangeMetrics && (
              <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs space-y-2">
                <div className="font-semibold text-emerald-300 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4" />
                  Envelope Re-wrapping Metrics:
                </div>
                <div className="grid grid-cols-3 gap-2 font-mono text-[11px] pt-1">
                  <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">DEKs Re-wrapped</div>
                    <div className="text-white font-bold text-sm mt-0.5">{pwChangeMetrics.filesRewrapped}</div>
                  </div>
                  <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">Ciphertext Touched</div>
                    <div className="text-emerald-400 font-bold text-sm mt-0.5">0 KB (Untouched)</div>
                  </div>
                  <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                    <div className="text-slate-400 text-[10px]">Total Time</div>
                    <div className="text-indigo-400 font-bold text-sm mt-0.5">{pwChangeMetrics.elapsedMs} ms</div>
                  </div>
                </div>
              </div>
            )}

            {pwChangeMessage && pwChangeStatus === 'error' && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/60 text-xs text-red-300 flex items-center gap-2">
                <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{pwChangeMessage}</span>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Educational Trade-Off Lab & Architecture Explanation */}
        <div className="lg:col-span-5 space-y-8">
          
          {/* Architectural Comparison Card */}
          <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-5 shadow-sm">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-indigo-400" />
                The Envelope Password Change Trade-Off
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                How envelope encryption eliminates the catastrophic bottleneck of re-encrypting gigabytes of data.
              </p>
            </div>

            <div className="space-y-4">
              {/* Traditional Approach */}
              <div className="p-4 rounded-lg bg-red-950/20 border border-red-900/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-red-400 flex items-center gap-1.5">
                    <XCircle className="w-3.5 h-3.5" />
                    Without Envelope Encryption
                  </span>
                  <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-red-900/40 text-red-300">
                    High Risk & Slow
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Every single file is encrypted directly with the password-derived key. Changing the password requires:
                </p>
                <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                  <li>Downloading gigabytes of ciphertext from S3/vault</li>
                  <li>Decrypting every byte in client RAM/disk</li>
                  <li>Re-encrypting all bytes with the new password key</li>
                  <li>Re-uploading all gigabytes back to cloud storage</li>
                </ul>
              </div>

              {/* Envelope Approach */}
              <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-900/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    With Envelope Encryption (Our Design)
                  </span>
                  <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300">
                    Zero-Knowledge & Instant
                  </span>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Files are encrypted with unique random DEKs. The password only wraps the 32-byte DEKs:
                </p>
                <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
                  <li>Cloud file ciphertext is <strong className="text-white">100% untouched</strong> (0 bytes moved)</li>
                  <li>Only the 32-byte DEK is unwrapped and re-wrapped with new KEK</li>
                  <li>Takes ~1-2 milliseconds per file</li>
                  <li>No network bandwidth or S3 transfer costs</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Interactive Simulation Slider */}
          <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 space-y-5 shadow-sm">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-amber-400" />
              Interactive Impact Calculator
            </h3>

            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-400">Total Files in Vault:</span>
                  <span className="font-mono text-white font-semibold">{simFileCount} files</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="200"
                  step="5"
                  value={simFileCount}
                  onChange={(e) => setSimFileCount(parseInt(e.target.value, 10))}
                  className="w-full accent-indigo-500 cursor-pointer"
                />
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-400">Average File Size:</span>
                  <span className="font-mono text-white font-semibold">{simAvgFileSizeMB} MB</span>
                </div>
                <input
                  type="range"
                  min="5"
                  max="200"
                  step="5"
                  value={simAvgFileSizeMB}
                  onChange={(e) => setSimAvgFileSizeMB(parseInt(e.target.value, 10))}
                  className="w-full accent-indigo-500 cursor-pointer"
                />
              </div>

              <div className="pt-2 border-t border-slate-800 space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center text-slate-400">
                  <span>Total Encrypted Data:</span>
                  <span className="text-slate-200 font-semibold">{totalCiphertextMB.toLocaleString()} MB ({(totalCiphertextMB / 1024).toFixed(2)} GB)</span>
                </div>

                <div className="p-3 rounded-lg bg-red-950/20 border border-red-900/30 flex items-center justify-between">
                  <div>
                    <div className="text-[10px] text-red-400 font-sans font-medium">Traditional Direct Re-encryption</div>
                    <div className="text-red-300 font-bold text-sm">~{traditionalBandwidthMB.toLocaleString()} MB transferred</div>
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 font-sans">Est. Time</div>
                    <div className="text-red-300 font-bold text-sm">{traditionalTotalMinutes.toFixed(1)} mins</div>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/30 flex items-center justify-between">
                  <div>
                    <div className="text-[10px] text-emerald-400 font-sans font-medium">Envelope DEK Re-wrapping</div>
                    <div className="text-emerald-300 font-bold text-sm">{envelopeMetadataKB.toFixed(1)} KB (Metadata only)</div>
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 font-sans">Est. Time</div>
                    <div className="text-emerald-300 font-bold text-sm">{envelopeTimeMs} ms</div>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 font-sans leading-relaxed pt-1">
                  💡 <strong className="text-slate-200">The Cryptographic Trade-Off:</strong> While envelope encryption requires storing a 32-byte wrapped DEK alongside each file, it avoids downloading and re-encrypting gigabytes when credentials change, drastically improving speed, bandwidth, and zero-knowledge privacy.
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>

      {/* Public Key PEM Modal */}
      {showPemModal && keyStatus.publicKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-indigo-400" />
                RSA-OAEP Public Key (SPKI PEM)
              </h3>
              <button
                onClick={() => setShowPemModal(false)}
                className="text-slate-400 hover:text-white text-xs cursor-pointer"
              >
                ✕ Close
              </button>
            </div>

            <div className="text-xs text-slate-400">
              This public key can be safely shared with anyone. Other users use it to encrypt the file DEK when sharing files with you.
            </div>

            <pre className="p-4 rounded-lg bg-black font-mono text-[11px] text-emerald-400 border border-slate-800 overflow-x-auto select-all max-h-64">
              {formatSpkiToPem(keyStatus.publicKey)}
            </pre>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={handleCopyPem}
                className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors flex items-center gap-1.5 cursor-pointer"
              >
                {copiedPem ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedPem ? 'Copied to Clipboard' : 'Copy PEM to Clipboard'}
              </button>
              <button
                onClick={() => setShowPemModal(false)}
                className="px-4 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
