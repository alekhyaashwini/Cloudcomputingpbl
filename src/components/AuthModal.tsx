import React, { useState } from 'react';
import { UserProfile } from '../types';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (user: UserProfile, token: string) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('cs_student');
  const [email, setEmail] = useState('student@college.edu');
  const [password, setPassword] = useState('Student@123');
  const [confirmPassword, setConfirmPassword] = useState('Student@123');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login';
    const payload = mode === 'register' 
      ? { username, email, password }
      : { identifier: username || email, password };

    if (mode === 'register' && password !== confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Authentication failed');
      }
      onSuccess(data.user, data.token);
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fillQuickDemoUser = (userType: 'student' | 'examiner' | 'attacker') => {
    if (userType === 'student') {
      setUsername('cs_student');
      setEmail('student@college.edu');
      setPassword('Student@123');
    } else if (userType === 'examiner') {
      setUsername('prof_sharma');
      setEmail('examiner@college.edu');
      setPassword('Faculty@2026');
    } else {
      setUsername('malicious_actor');
      setEmail('attacker@external.net');
      setPassword('Attacker#999');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0F172A] border border-slate-700 rounded-xl max-w-md w-full p-6 shadow-2xl">
        
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <div className="text-xs font-mono text-indigo-400">Vault Session Security</div>
            <h3 className="text-lg font-bold text-white mt-0.5">
              {mode === 'login' ? 'Authenticate to Vault' : 'Register New Account'}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>

        {/* Quick Demo Switcher Buttons */}
        <div className="mt-4 p-3 bg-slate-900/80 rounded-lg border border-slate-800">
          <div className="text-xs font-medium text-slate-400 mb-2">PBL Quick Switcher (Test Cross-User Access):</div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => fillQuickDemoUser('student')}
              className="px-2 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-indigo-300 rounded border border-slate-700 cursor-pointer"
            >
              Primary Student
            </button>
            <button
              type="button"
              onClick={() => fillQuickDemoUser('examiner')}
              className="px-2 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-emerald-300 rounded border border-slate-700 cursor-pointer"
            >
              Faculty Reviewer
            </button>
            <button
              type="button"
              onClick={() => fillQuickDemoUser('attacker')}
              className="px-2 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-rose-300 rounded border border-slate-700 cursor-pointer"
            >
              Attacker (Tenant 2)
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-3.5">
          {error && (
            <div className="p-3 bg-red-950/60 border border-red-800 rounded text-red-200 text-xs">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:border-indigo-500 outline-none"
              required
            />
          </div>

          {mode === 'register' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">College Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:border-indigo-500 outline-none"
                required
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:border-indigo-500 outline-none"
              required
            />
          </div>

          {mode === 'register' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-xs text-white focus:border-indigo-500 outline-none"
                required
              />
            </div>
          )}

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-500 rounded-lg transition-colors cursor-pointer disabled:opacity-50 shadow-sm"
            >
              {loading ? 'Authenticating...' : mode === 'login' ? 'Sign In to Vault' : 'Create Encrypted Account'}
            </button>
          </div>

          <div className="text-center text-xs text-slate-400 pt-2">
            {mode === 'login' ? (
              <span>
                Need a new account?{' '}
                <button
                  type="button"
                  onClick={() => setMode('register')}
                  className="text-indigo-400 hover:underline cursor-pointer"
                >
                  Register here
                </button>
              </span>
            ) : (
              <span>
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => setMode('login')}
                  className="text-indigo-400 hover:underline cursor-pointer"
                >
                  Sign in
                </button>
              </span>
            )}
          </div>
        </form>

      </div>
    </div>
  );
};
