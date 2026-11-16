import { useState } from 'react'
import { useAuth } from '../context/AuthContext'
import { useNavigate } from 'react-router-dom'
import { User, Mail, Shield, LogOut, Key, Clock } from 'lucide-react'

export default function Profile() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [loggingOut, setLoggingOut] = useState(false)

  async function handleLogout() {
    setLoggingOut(true)
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="max-w-xl mx-auto space-y-6 animate-slide-up">
      <h1 className="text-2xl font-bold text-white">Profile</h1>

      {/* Avatar card */}
      <div className="card p-6 flex items-center gap-5">
        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-600 to-violet-600 flex items-center justify-center text-white text-2xl font-bold shadow-lg shadow-blue-900/40 shrink-0">
          {user?.email?.[0]?.toUpperCase() ?? 'U'}
        </div>
        <div>
          <p className="text-lg font-semibold text-white">{user?.email}</p>
          <p className="text-sm text-slate-500 capitalize mt-0.5">{user?.role} account</p>
        </div>
      </div>

      {/* Account details */}
      <div className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white">Account Details</h2>
        <div className="space-y-3">
          <InfoRow icon={<Mail size={14} />} label="Email">
            <span className="text-slate-200 text-sm">{user?.email}</span>
          </InfoRow>
          <InfoRow icon={<Shield size={14} />} label="Role">
            <span className="text-slate-200 text-sm capitalize">{user?.role}</span>
          </InfoRow>
          <InfoRow icon={<User size={14} />} label="User ID">
            <code className="text-xs text-slate-400 font-mono">{user?.id}</code>
          </InfoRow>
        </div>
      </div>

      {/* Security */}
      <div className="card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white">Security</h2>
        <div className="space-y-3 text-sm text-slate-400">
          <div className="flex items-center gap-3 p-3 rounded-lg bg-white/3">
            <Key size={14} className="text-slate-500" />
            <div>
              <p className="text-xs text-slate-500">Session Tokens</p>
              <p className="text-slate-300 text-sm">Access token: 15 min · Refresh token: 7 days</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-lg bg-white/3">
            <Clock size={14} className="text-slate-500" />
            <div>
              <p className="text-xs text-slate-500">Authentication</p>
              <p className="text-slate-300 text-sm">JWT RS256 · Automatic token refresh enabled</p>
            </div>
          </div>
        </div>
      </div>

      {/* Logout */}
      <button
        onClick={handleLogout}
        disabled={loggingOut}
        className="btn-danger w-full justify-center py-3"
      >
        <LogOut size={16} />
        {loggingOut ? 'Signing out…' : 'Sign out of all sessions'}
      </button>
    </div>
  )
}

function InfoRow({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-white/3">
      <span className="text-slate-500 mt-0.5 shrink-0">{icon}</span>
      <div>
        <p className="text-xs text-slate-500 mb-0.5">{label}</p>
        {children}
      </div>
    </div>
  )
}
