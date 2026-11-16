import { Navigate, Outlet } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

export function ProtectedRoute() {
  const { authed } = useAuth()
  return authed ? <Outlet /> : <Navigate to="/login" replace />
}

export function GuestRoute() {
  const { authed } = useAuth()
  return authed ? <Navigate to="/dashboard" replace /> : <Outlet />
}
