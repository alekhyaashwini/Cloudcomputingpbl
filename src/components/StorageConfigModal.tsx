import React, { useState, useEffect } from 'react';
import { StorageConfig } from '../types';

interface StorageConfigModalProps {
  config: StorageConfig;
  isOpen: boolean;
  onClose: () => void;
  onSave: (updated: {
    backend: 'local' | 's3';
    s3Bucket: string;
    s3Region: string;
    s3Endpoint?: string;
    forcePathStyle?: boolean;
    awsAccessKeyId?: string;
    awsSecretAccessKey?: string;
  }) => Promise<void>;
}

export const StorageConfigModal: React.FC<StorageConfigModalProps> = ({
  config,
  isOpen,
  onClose,
  onSave
}) => {
  const [backend, setBackend] = useState<'local' | 's3'>(config.backend);
  const [preset, setPreset] = useState<'local' | 'minio' | 'aws'>(
    config.backend === 'local' ? 'local' : (config.s3Endpoint?.includes('9000') || config.provider === 'minio' ? 'minio' : 'aws')
  );
  const [s3Bucket, setS3Bucket] = useState(config.s3Bucket || 'secure-vault-bucket');
  const [s3Region, setS3Region] = useState(config.s3Region || 'us-east-1');
  const [s3Endpoint, setS3Endpoint] = useState(config.s3Endpoint || 'http://localhost:9000');
  const [forcePathStyle, setForcePathStyle] = useState(config.forcePathStyle ?? true);
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ connected?: boolean; message?: string } | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setBackend(config.backend);
      const isMinio = Boolean(config.s3Endpoint?.includes('9000') || config.provider === 'minio' || (!config.s3Endpoint && config.backend === 's3' && config.hasAwsKeys === false));
      setPreset(config.backend === 'local' ? 'local' : (isMinio ? 'minio' : 'aws'));
      setS3Bucket(config.s3Bucket || 'secure-vault-bucket');
      setS3Region(config.s3Region || 'us-east-1');
      setS3Endpoint(config.s3Endpoint || (isMinio ? 'http://localhost:9000' : ''));
      setForcePathStyle(config.forcePathStyle ?? true);
      setTestResult(null);
      setStatusMsg(null);
    }
  }, [isOpen, config]);

  if (!isOpen) return null;

  const handlePresetChange = (selected: 'local' | 'minio' | 'aws') => {
    setPreset(selected);
    if (selected === 'local') {
      setBackend('local');
    } else if (selected === 'minio') {
      setBackend('s3');
      setS3Endpoint('http://localhost:9000');
      setForcePathStyle(true);
      setS3Bucket('secure-vault-bucket');
      setAccessKey('minioadmin');
      setSecretKey('minioadmin');
    } else if (selected === 'aws') {
      setBackend('s3');
      setS3Endpoint('');
      setForcePathStyle(false);
      setS3Bucket('secure-vault-bucket');
      setAccessKey('');
      setSecretKey('');
    }
    setTestResult(null);
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch('/api/storage/test');
      const data = await res.json();
      setTestResult({
        connected: data.connected,
        message: data.message
      });
    } catch (err: any) {
      setTestResult({
        connected: false,
        message: `Connection test error: ${err.message}`
      });
    } finally {
      setTesting(false);
    }
  };

  const handleCreateBucket = async () => {
    setTesting(true);
    try {
      const res = await fetch('/api/storage/bucket/create', { method: 'POST' });
      const data = await res.json();
      setTestResult({
        connected: data.success,
        message: data.message
      });
    } catch (err: any) {
      setTestResult({
        connected: false,
        message: `Create bucket error: ${err.message}`
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setStatusMsg(null);

    try {
      await onSave({
        backend,
        s3Bucket,
        s3Region,
        s3Endpoint: backend === 's3' ? s3Endpoint : undefined,
        forcePathStyle: backend === 's3' ? forcePathStyle : undefined,
        awsAccessKeyId: accessKey ? accessKey : undefined,
        awsSecretAccessKey: secretKey ? secretKey : undefined
      });
      setStatusMsg(`Storage configuration successfully switched to ${backend.toUpperCase()}`);
      setTimeout(() => {
        onClose();
      }, 1000);
    } catch (err: any) {
      setStatusMsg(`Error updating configuration: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-lg w-full p-6 shadow-2xl overflow-y-auto max-h-[90vh]">
        
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <div className="text-xs font-mono text-indigo-400">Storage Abstraction Layer (S3 / MinIO)</div>
            <h3 className="text-lg font-bold text-white mt-0.5">Storage Backend Configuration</h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          
          {/* Preset Selector */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Select Storage Environment
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handlePresetChange('local')}
                className={`p-2.5 rounded-lg border text-left transition-colors cursor-pointer ${
                  preset === 'local'
                    ? 'border-indigo-500 bg-indigo-950/50 text-white ring-1 ring-indigo-500'
                    : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="font-semibold text-xs">Local Vault</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Disk / memory</div>
              </button>

              <button
                type="button"
                onClick={() => handlePresetChange('minio')}
                className={`p-2.5 rounded-lg border text-left transition-colors cursor-pointer ${
                  preset === 'minio'
                    ? 'border-emerald-500 bg-emerald-950/50 text-white ring-1 ring-emerald-500'
                    : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="font-semibold text-xs text-emerald-400">MinIO (Local)</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Docker :9000</div>
              </button>

              <button
                type="button"
                onClick={() => handlePresetChange('aws')}
                className={`p-2.5 rounded-lg border text-left transition-colors cursor-pointer ${
                  preset === 'aws'
                    ? 'border-amber-500 bg-amber-950/50 text-white ring-1 ring-amber-500'
                    : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200'
                }`}
              >
                <div className="font-semibold text-xs text-amber-400">AWS S3 (Cloud)</div>
                <div className="text-[10px] text-slate-500 mt-0.5">Production bucket</div>
              </button>
            </div>
          </div>

          {/* MinIO / S3 Settings */}
          {backend === 's3' && (
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                  {preset === 'minio' ? 'MinIO Local Storage Settings' : 'AWS S3 Cloud Settings'}
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                  AWS SDK v3 Compatible
                </span>
              </div>

              {/* Endpoint */}
              <div>
                <label className="block text-xs text-slate-400 mb-1">
                  S3 Endpoint URL {preset === 'minio' && <span className="text-emerald-400 font-mono">(Local MinIO API)</span>}
                </label>
                <input
                  type="text"
                  value={s3Endpoint}
                  onChange={(e) => setS3Endpoint(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:border-indigo-500 outline-none"
                  placeholder="http://localhost:9000 (leave empty for AWS S3)"
                />
                <p className="text-[10px] text-slate-500 mt-0.5">
                  Set to <code className="text-slate-300">http://localhost:9000</code> for MinIO or leave blank for AWS S3 cloud.
                </p>
              </div>

              {/* Bucket & Region */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Bucket Name</label>
                  <input
                    type="text"
                    value={s3Bucket}
                    onChange={(e) => setS3Bucket(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:border-indigo-500 outline-none"
                    placeholder="secure-vault-bucket"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Region</label>
                  <input
                    type="text"
                    value={s3Region}
                    onChange={(e) => setS3Region(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:border-indigo-500 outline-none"
                    placeholder="us-east-1"
                    required
                  />
                </div>
              </div>

              {/* Path style toggle */}
              <div className="flex items-center justify-between pt-1">
                <span className="text-xs text-slate-400">Path-Style Addressing (Required for MinIO):</span>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={forcePathStyle}
                    onChange={(e) => setForcePathStyle(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-600"></div>
                </label>
              </div>

              {/* Access Keys */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Access Key ID</label>
                  <input
                    type="text"
                    value={accessKey}
                    onChange={(e) => setAccessKey(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:border-indigo-500 outline-none"
                    placeholder={preset === 'minio' ? 'minioadmin' : 'AKIA...'}
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Secret Access Key</label>
                  <input
                    type="password"
                    value={secretKey}
                    onChange={(e) => setSecretKey(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-white font-mono focus:border-indigo-500 outline-none"
                    placeholder={preset === 'minio' ? 'minioadmin' : 'AWS Secret Key'}
                  />
                </div>
              </div>

              {/* Diagnostic Tools */}
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between gap-2">
                <button
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testing}
                  className="px-2.5 py-1 text-[11px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition cursor-pointer disabled:opacity-50"
                >
                  {testing ? 'Testing...' : '⚡ Test Connection'}
                </button>
                <button
                  type="button"
                  onClick={handleCreateBucket}
                  disabled={testing}
                  className="px-2.5 py-1 text-[11px] font-mono bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded transition cursor-pointer disabled:opacity-50"
                >
                  Create Bucket If Missing
                </button>
              </div>

              {testResult && (
                <div className={`p-2 rounded text-xs font-mono ${
                  testResult.connected ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-800' : 'bg-rose-950/60 text-rose-300 border border-rose-800'
                }`}>
                  {testResult.connected ? '✓ ' : '✕ '} {testResult.message}
                </div>
              )}
            </div>
          )}

          {statusMsg && (
            <div className="p-2.5 rounded bg-slate-800 text-xs text-indigo-300 font-mono">
              {statusMsg}
            </div>
          )}

          <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white rounded-lg transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Apply Adapter'}
            </button>
          </div>

        </form>

      </div>
    </div>
  );
};
