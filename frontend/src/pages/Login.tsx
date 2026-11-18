import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, LogIn } from 'lucide-react'
import { login } from '../services/authService'
import { useAuth } from '../context/AuthContext'
import { Alert } from '../components/common/Alert'
import { Spinner } from '../components/common/Spinner'
import { extractApiError } from '../utils/format'

export default function Login() {
  const { setAuth } = useAuth()
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const { user } = await login(email, password)
      setAuth(user)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(extractApiError(err, 'Login failed. Please check your credentials.'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-600/8 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-violet-600/8 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-sm relative animate-slide-up">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-600 to-violet-600 shadow-2xl shadow-blue-900/50 mb-4">
            <Shield size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">CipherGuard AI</h1>
          <p className="text-slate-500 text-sm mt-1">AI-Powered Malware Detection</p>
        </div>

        {/* Card */}
        <div className="card p-6 shadow-2xl shadow-black/40">
          <h2 className="text-lg font-semibold text-white mb-1">Sign in</h2>
          <p className="text-slate-500 text-sm mb-6">Enter your credentials to continue</p>

          {error && (
            <div className="mb-4">
              <Alert variant="error" message={error} onDismiss={() => setError(null)} />
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Email address</label>
              <input
                type="email"
                className="input-field"
                placeholder="you@example.com"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  className="input-field pr-10"
                  placeholder="••••••••"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                  tabIndex={-1}
                >
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn-primary w-full justify-center py-3"
              disabled={loading}
            >
              {loading ? <Spinner size={16} label="Signing in…" /> : (<><LogIn size={16} />Sign in</>)}
            </button>
          </form>

          <p className="mt-5 text-center text-sm text-slate-500">
            Don't have an account?{' '}
            <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
              Create account
            </Link>
          </p>
        </div>

        <p className="mt-4 text-center text-xs text-slate-600">
          CipherGuard AI · Secure Malware Analysis Platform
        </p>
      </div>
    </div>
  )
}
