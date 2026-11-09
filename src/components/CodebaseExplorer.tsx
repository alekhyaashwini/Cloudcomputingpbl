import React, { useState } from 'react';
import JSZip from 'jszip';
import { MERN_CODEBASE_FILES, FLASK_CODEBASE_FILES, ProjectFile } from '../data/codebaseFiles';

export const CodebaseExplorer: React.FC = () => {
  const [activeStack, setActiveStack] = useState<'mern' | 'flask'>('mern');
  const currentFileList = activeStack === 'mern' ? MERN_CODEBASE_FILES : FLASK_CODEBASE_FILES;
  const [selectedFile, setSelectedFile] = useState<ProjectFile>(currentFileList[0]);
  const [copied, setCopied] = useState(false);
  const [downloadingZip, setDownloadingZip] = useState(false);

  const handleStackChange = (stack: 'mern' | 'flask') => {
    setActiveStack(stack);
    const files = stack === 'mern' ? MERN_CODEBASE_FILES : FLASK_CODEBASE_FILES;
    setSelectedFile(files[0]);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(selectedFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadZip = async () => {
    setDownloadingZip(true);
    try {
      const zip = new JSZip();
      const folderName = activeStack === 'mern' ? 'secure-cloud-storage-mern' : 'secure-cloud-storage-flask';
      const rootFolder = zip.folder(folderName);
      if (!rootFolder) throw new Error('Could not create zip folder');

      currentFileList.forEach(file => {
        rootFolder.file(file.path, file.content);
      });

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${folderName}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to build zip:', err);
      alert('Error generating zip bundle.');
    } finally {
      setDownloadingZip(false);
    }
  };

  const folders = Array.from(new Set(currentFileList.map(f => f.folder)));

  return (
    <div className="space-y-6">
      
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            PBL Project Codebase & Full-Stack Architectures
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Complete, production-ready source code with package.json, Docker Compose, and Web Crypto API.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Stack Selector */}
          <div className="flex items-center bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => handleStackChange('mern')}
              className={`px-3 py-1.5 text-xs font-semibold rounded transition-colors cursor-pointer ${
                activeStack === 'mern'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              MERN + Web Crypto + S3/MinIO
            </button>
            <button
              onClick={() => handleStackChange('flask')}
              className={`px-3 py-1.5 text-xs font-semibold rounded transition-colors cursor-pointer ${
                activeStack === 'flask'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Python 3.11 + Flask
            </button>
          </div>

          <button
            onClick={handleDownloadZip}
            disabled={downloadingZip}
            className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors flex items-center gap-2 cursor-pointer shadow-sm disabled:opacity-50"
          >
            <span>📦</span>
            <span>{downloadingZip ? 'Packaging Zip...' : `Download ${activeStack.toUpperCase()} (.zip)`}</span>
          </button>
        </div>
      </div>

      {/* Stack Summary Banner */}
      <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 text-xs text-slate-300 flex flex-wrap items-center justify-between gap-3">
        {activeStack === 'mern' ? (
          <div>
            <strong className="text-white">Active Stack:</strong> React.js (Vite) + Web Crypto API (Client-Side Zero-Knowledge) + Node/Express + MongoDB (Mongoose) + MinIO / AWS S3 + Docker Compose.
          </div>
        ) : (
          <div>
            <strong className="text-white">Active Stack:</strong> Python 3.11 + Flask + Cryptography AES-256-GCM + SQLite + Amazon S3 / Local Vault.
          </div>
        )}
        <div className="text-indigo-400 font-mono text-[11px]">
          {currentFileList.length} Files in Repository
        </div>
      </div>

      {/* Explorer Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 bg-slate-900/60 rounded-xl border border-slate-800 overflow-hidden min-h-[600px]">
        
        {/* Left Sidebar: File Tree */}
        <div className="lg:col-span-4 border-b lg:border-b-0 lg:border-r border-slate-800 p-4 bg-slate-950/40">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
            {activeStack === 'mern' ? 'MERN Zero-Knowledge Layout' : 'Python Flask Layout'}
          </div>

          <div className="space-y-4">
            {folders.map(folder => (
              <div key={folder}>
                <div className="text-xs font-mono text-indigo-400 font-semibold mb-1 flex items-center gap-1.5">
                  <span>📁</span>
                  <span>{folder === 'Root' ? './' : `${folder}/`}</span>
                </div>
                <div className="space-y-0.5 pl-4 border-l border-slate-800">
                  {currentFileList.filter(f => f.folder === folder).map(file => (
                    <button
                      key={file.path}
                      onClick={() => setSelectedFile(file)}
                      className={`w-full text-left px-2.5 py-1.5 text-xs rounded transition-colors flex items-center justify-between cursor-pointer ${
                        selectedFile.path === file.path
                          ? 'bg-indigo-600 text-white font-medium'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                      }`}
                    >
                      <span className="truncate">{file.name}</span>
                      <span className="text-[10px] opacity-60 uppercase font-mono">{file.language}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Code Display */}
        <div className="lg:col-span-8 flex flex-col p-4 bg-slate-950/80">
          
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-indigo-400 font-semibold">
                {selectedFile.path}
              </span>
              <span className="text-[11px] text-slate-500 font-mono">
                ({selectedFile.content.split('\n').length} lines)
              </span>
            </div>

            <button
              onClick={handleCopy}
              className="px-3 py-1 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors cursor-pointer"
            >
              {copied ? '✓ Copied to Clipboard' : 'Copy File Content'}
            </button>
          </div>

          <div className="flex-grow overflow-auto font-mono text-xs text-slate-300 bg-black/40 p-4 rounded-lg border border-slate-800 leading-relaxed max-h-[550px] whitespace-pre">
            {selectedFile.content}
          </div>

        </div>

      </div>

    </div>
  );
};
