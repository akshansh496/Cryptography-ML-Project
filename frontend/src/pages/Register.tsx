import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, UserPlus, CheckCircle2, XCircle } from 'lucide-react'
import { register, login } from '../services/authService'
import { useAuth } from '../context/AuthContext'
import { Alert } from '../components/common/Alert'
import { Spinner } from '../components/common/Spinner'
import { extractApiError } from '../utils/format'

// Password requirements exactly matching backend validators.ts
const PW_RULES = [
  { label: 'At least 8 characters', test: (p: string) => p.length >= 8 },
  { label: 'At least 1 uppercase letter (A-Z)', test: (p: string) => /[A-Z]/.test(p) },
  { label: 'At least 1 number (0-9)', test: (p: string) => /[0-9]/.test(p) },
  { label: 'At least 1 special character (!@#…)', test: (p: string) => /[^A-Za-z0-9]/.test(p) },
]

export default function Register() {
  const { setAuth } = useAuth()
  const navigate = useNavigate()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const pwOk = PW_RULES.every((r) => r.test(password))
  const confirmOk = password === confirm && confirm.length > 0

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    if (!pwOk) { setError('Password does not meet all requirements.'); return }
    if (!confirmOk) { setError('Passwords do not match.'); return }

    setLoading(true)
    try {
      await register(email, password)
      setSuccess(true)
      // Auto-login after registration
      const { user } = await login(email, password)
      setAuth(user)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      setError(extractApiError(err, 'Registration failed. Please try again.'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-violet-600/8 rounded-full blur-3xl" />
        <div className="absolute bottom-1/3 left-1/3 w-96 h-96 bg-blue-600/8 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-sm relative animate-slide-up">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-600 to-violet-600 shadow-2xl shadow-blue-900/50 mb-4">
            <Shield size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">CipherGuard AI</h1>
          <p className="text-slate-500 text-sm mt-1">Create your secure account</p>
        </div>

        <div className="card p-6 shadow-2xl shadow-black/40">
          <h2 className="text-lg font-semibold text-white mb-1">Create account</h2>
          <p className="text-slate-500 text-sm mb-6">Start scanning files for threats</p>

          {error && (
            <div className="mb-4">
              <Alert variant="error" message={error} onDismiss={() => setError(null)} />
            </div>
          )}
          {success && (
            <div className="mb-4">
              <Alert variant="success" message="Account created! Signing you in…" />
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
                  autoComplete="new-password"
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

              {/* Live password rules */}
              {password.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {PW_RULES.map((rule) => (
                    <li key={rule.label} className={`flex items-center gap-1.5 text-xs ${rule.test(password) ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {rule.test(password)
                        ? <CheckCircle2 size={12} />
                        : <XCircle size={12} className="text-slate-600" />}
                      {rule.label}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Confirm password</label>
              <input
                type={showPw ? 'text' : 'password'}
                className={`input-field ${confirm.length > 0 && !confirmOk ? 'border-red-500/50 focus:ring-red-500/50' : ''}`}
                placeholder="••••••••"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
                disabled={loading}
              />
              {confirm.length > 0 && !confirmOk && (
                <p className="mt-1 text-xs text-red-400">Passwords do not match</p>
              )}
            </div>

            <button
              type="submit"
              className="btn-primary w-full justify-center py-3"
              disabled={loading || !pwOk || !confirmOk}
            >
              {loading ? <Spinner size={16} label="Creating account…" /> : (<><UserPlus size={16} />Create account</>)}
            </button>
          </form>

          <p className="mt-5 text-center text-sm text-slate-500">
            Already have an account?{' '}
            <Link to="/login" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
