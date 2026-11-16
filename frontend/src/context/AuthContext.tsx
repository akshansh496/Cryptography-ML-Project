import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { User, getStoredUser, clearTokens, isAuthenticated, logout as apiLogout } from '../services/authService'

interface AuthContextValue {
  user: User | null
  authed: boolean
  setAuth: (user: User) => void
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => getStoredUser())

  const logout = useCallback(async () => {
    await apiLogout()
    setUser(null)
  }, [])

  // Listen for auth:logout events (from axios interceptor on 401)
  useEffect(() => {
    const handler = () => {
      clearTokens()
      setUser(null)
    }
    window.addEventListener('auth:logout', handler)
    return () => window.removeEventListener('auth:logout', handler)
  }, [])

  const setAuth = useCallback((u: User) => setUser(u), [])

  return (
    <AuthContext.Provider value={{ user, authed: isAuthenticated() && !!user, setAuth, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
