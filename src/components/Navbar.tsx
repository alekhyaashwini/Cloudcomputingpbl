import React from 'react';
import { UserProfile, StorageConfig } from '../types';

interface NavbarProps {
  activeTab: 'dashboard' | 'envelope-storage' | 'tamper-lab' | 'settings' | 'codebase' | 'docs' | 'tests';
  setActiveTab: (tab: 'dashboard' | 'envelope-storage' | 'tamper-lab' | 'settings' | 'codebase' | 'docs' | 'tests') => void;
  user: UserProfile | null;
  onOpenAuth: () => void;
  onLogout: () => void;
  storageConfig: StorageConfig;
  onOpenStorageConfig: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  user,
  onOpenAuth,
  onLogout,
  storageConfig,
  onOpenStorageConfig
}) => {
  return (
    <header className="border-b border-slate-800 bg-[#0F172A] sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        
        {/* Zone 1: Brand Wordmark (Single text element) */}
        <div className="flex items-center gap-3 shrink-0">
          <button 
            onClick={() => setActiveTab('envelope-storage')} 
            className="text-left font-bold text-lg tracking-tight text-white hover:text-indigo-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 cursor-pointer"
          >
            <span className="w-8 h-8 rounded bg-indigo-600 flex items-center justify-center text-white font-mono text-sm font-bold shadow-sm">
              AES
            </span>
            <span>CloudVault</span>
          </button>
          
          <button 
            onClick={onOpenStorageConfig}
            className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded border border-slate-700 transition-colors cursor-pointer"
            title="Configure Cloud Storage Backend"
          >
            <span className={`w-1.5 h-1.5 rounded-full ${storageConfig.backend === 's3' ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
            <span>{storageConfig.backend === 's3' ? 'AWS S3' : 'Local Vault'}</span>
          </button>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden md:flex items-center gap-5 text-sm font-medium">
          <button
            onClick={() => setActiveTab('envelope-storage')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 flex items-center gap-1.5 ${
              activeTab === 'envelope-storage'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Envelope Vault</span>
            <span className="px-1.5 py-0.2 text-[10px] font-mono bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/30">React</span>
          </button>

          <button
            onClick={() => setActiveTab('dashboard')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 ${
              activeTab === 'dashboard'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Dashboard
          </button>

          <button
            onClick={() => setActiveTab('settings')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 flex items-center gap-1.5 ${
              activeTab === 'settings'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Key & Vault Settings</span>
            <span className="px-1.5 py-0.2 text-[9px] font-mono bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30">RSA-OAEP</span>
          </button>

          <button
            onClick={() => setActiveTab('tamper-lab')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 ${
              activeTab === 'tamper-lab'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Integrity Lab
          </button>

          <button
            onClick={() => setActiveTab('tests')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 ${
              activeTab === 'tests'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Tests
          </button>

          <button
            onClick={() => setActiveTab('codebase')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 ${
              activeTab === 'codebase'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Codebase & Zip
          </button>

          <button
            onClick={() => setActiveTab('docs')}
            className={`whitespace-nowrap shrink-0 transition-colors cursor-pointer pb-1 ${
              activeTab === 'docs'
                ? 'text-indigo-400 border-b-2 border-indigo-500 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            PBL Report (25 Q&A)
          </button>
        </nav>

        {/* Zone 3: Primary Action / User Profile */}
        <div className="flex items-center gap-3 shrink-0">
          {user ? (
            <div className="flex items-center gap-3">
              <div className="hidden lg:block text-right text-xs">
                <div className="font-medium text-slate-200">{user.username}</div>
                <div className="text-slate-500">{user.email}</div>
              </div>
              <button
                onClick={onLogout}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Sign Out
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuth}
              className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded transition-colors whitespace-nowrap shrink-0 shadow-sm cursor-pointer"
            >
              Sign In to Vault
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
