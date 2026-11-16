import api from './api'

export interface User {
  id: string
  email: string
  role: string
}

export interface AuthTokens {
  accessToken: string
  refreshToken: string
  user: User
}

export interface RegisterResponse {
  id: string
  email: string
}

function saveTokens(tokens: { accessToken: string; refreshToken: string; user: User }) {
  localStorage.setItem('accessToken', tokens.accessToken)
  localStorage.setItem('refreshToken', tokens.refreshToken)
  localStorage.setItem('user', JSON.stringify(tokens.user))
}

export function clearTokens() {
  localStorage.removeItem('accessToken')
  localStorage.removeItem('refreshToken')
  localStorage.removeItem('user')
}

export function getStoredUser(): User | null {
  try {
    const raw = localStorage.getItem('user')
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function isAuthenticated(): boolean {
  return !!localStorage.getItem('accessToken')
}

export async function register(email: string, password: string): Promise<RegisterResponse> {
  const { data } = await api.post<RegisterResponse>('/api/auth/register', { email, password })
  return data
}

export async function login(email: string, password: string): Promise<AuthTokens> {
  const { data } = await api.post<AuthTokens>('/api/auth/login', { email, password })
  saveTokens(data)
  return data
}

export async function logout(): Promise<void> {
  const refreshToken = localStorage.getItem('refreshToken')
  if (refreshToken) {
    try {
      await api.post('/api/auth/logout', { refreshToken })
    } catch {
      // Best-effort: clear client side regardless
    }
  }
  clearTokens()
}
