import React, { useState, useEffect } from 'react';
import { UserProfile, StoredFile, StorageConfig } from './types';
import { Navbar } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { TamperLabView } from './components/TamperLabView';
import { CodebaseExplorer } from './components/CodebaseExplorer';
import { DocumentationView } from './components/DocumentationView';
import { TestMatrixView } from './components/TestMatrixView';
import { CryptoInspectorModal } from './components/CryptoInspectorModal';
import { StorageConfigModal } from './components/StorageConfigModal';
import { AuthModal } from './components/AuthModal';
import FileStorage from './components/FileStorage.jsx';
import { SettingsView } from './components/SettingsView';

export default function App() {
  const [activeTab, setActiveTab] = useState<'envelope-storage' | 'dashboard' | 'tamper-lab' | 'settings' | 'codebase' | 'docs' | 'tests'>('envelope-storage');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [files, setFiles] = useState<StoredFile[]>([]);
  const [loadingFiles, setLoadingFiles] = useState(false);
  
  // Modals state
  const [inspectFileId, setInspectFileId] = useState<string | null>(null);
  const [isStorageModalOpen, setIsStorageModalOpen] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

  // Storage config
  const [storageConfig, setStorageConfig] = useState<StorageConfig>({
    backend: 'local',
    s3Bucket: 'secure-encrypted-college-vault',
    s3Region: 'us-east-1',
    hasAwsKeys: false
  });

  // Auto-authenticate default demo user on mount for smooth testing
  useEffect(() => {
    // Attempt auto-login as demo student
    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'cs_student', password: 'Student@123' })
    })
      .then(res => res.json())
      .then(data => {
        if (data.token && data.user) {
          setUser(data.user);
          setToken(data.token);
        }
      })
      .catch(err => {
        console.warn('Auto-login notice:', err);
      });

    // Fetch storage configuration
    fetch('/api/storage/config')
      .then(res => res.json())
      .then(cfg => {
        setStorageConfig(cfg);
      })
      .catch(err => {
        console.warn('Storage config notice:', err);
      });
  }, []);

  // Fetch files whenever user or token changes
  const fetchFiles = () => {
    if (!token) return;
    setLoadingFiles(true);
    fetch('/api/files/list', {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => {
        if (!res.ok) throw new Error('Unauthorized');
        return res.json();
      })
      .then(data => {
        setFiles(data.files || []);
        setLoadingFiles(false);
      })
      .catch(err => {
        console.warn('Fetch files notice:', err);
        setLoadingFiles(false);
      });
  };

  useEffect(() => {
    if (token) {
      fetchFiles();
    } else {
      setFiles([]);
    }
  }, [token]);

  const handleLogout = () => {
    if (token) {
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => {});
    }
    setUser(null);
    setToken(null);
  };

  const handleStorageSave = async (updated: {
    backend: 'local' | 's3';
    s3Bucket: string;
    s3Region: string;
    s3Endpoint?: string;
    forcePathStyle?: boolean;
    awsAccessKeyId?: string;
    awsSecretAccessKey?: string;
  }) => {
    const res = await fetch('/api/storage/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updated)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    setStorageConfig(data.config);
    fetchFiles();
  };

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      
      {/* Top Bar Navigation adhering to Top Bar Contract */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        user={user}
        onOpenAuth={() => setIsAuthModalOpen(true)}
        onLogout={handleLogout}
        storageConfig={storageConfig}
        onOpenStorageConfig={() => setIsStorageModalOpen(true)}
      />

      {/* Main Viewport Container */}
      <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        {activeTab === 'envelope-storage' && (
          <FileStorage />
        )}

        {user ? (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                files={files}
                user={user}
                token={token!}
                storageConfig={storageConfig}
                onRefreshFiles={fetchFiles}
                onInspectCrypto={(fileId) => setInspectFileId(fileId)}
                onOpenStorageConfig={() => setIsStorageModalOpen(true)}
              />
            )}

            {activeTab === 'settings' && (
              <SettingsView
                user={user}
                token={token}
                onRefreshUser={fetchFiles}
                onLogout={handleLogout}
              />
            )}

            {activeTab === 'tamper-lab' && (
              <TamperLabView />
            )}

            {activeTab === 'tests' && (
              <TestMatrixView />
            )}

            {activeTab === 'codebase' && (
              <CodebaseExplorer />
            )}

            {activeTab === 'docs' && (
              <DocumentationView />
            )}
          </>
        ) : (
          <div className="py-16 text-center max-w-md mx-auto space-y-4">
            <div className="w-16 h-16 rounded-full bg-indigo-600/20 border border-indigo-500/30 mx-auto flex items-center justify-center text-indigo-400 text-2xl font-bold">
              🔒
            </div>
            <h2 className="text-xl font-bold text-white">Vault Access Restricted</h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Please sign in with your credentials to derive your encryption keys and inspect your encrypted cloud files.
            </p>
            <button
              onClick={() => setIsAuthModalOpen(true)}
              className="px-6 py-2.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors cursor-pointer shadow-md"
            >
              Sign In to Encrypted Vault
            </button>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#0F172A] py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>
            <span>B.Tech CSE Project-Based Learning (PBL)</span>
            <span className="mx-2">·</span>
            <span>Secure Cloud File Storage Using AES-256-GCM Authenticated Encryption</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
            <span>NIST SP 800-38D</span>
            <span>·</span>
            <span>PBKDF2-HMAC-SHA256 (100k)</span>
            <span>·</span>
            <span>Amazon S3 & Local Adapters</span>
          </div>
        </div>
      </footer>

      {/* Modals */}
      <CryptoInspectorModal
        fileId={inspectFileId}
        token={token}
        onClose={() => setInspectFileId(null)}
      />

      <StorageConfigModal
        config={storageConfig}
        isOpen={isStorageModalOpen}
        onClose={() => setIsStorageModalOpen(false)}
        onSave={handleStorageSave}
      />

      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onSuccess={(newUser, newToken) => {
          setUser(newUser);
          setToken(newToken);
        }}
      />

    </div>
  );
}
