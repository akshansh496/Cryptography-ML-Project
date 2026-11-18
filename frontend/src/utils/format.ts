import type { Scan } from '../services/scanService'

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

export function formatDate(iso: string): string {
  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(iso))
}

export function formatDateShort(iso: string): string {
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }).format(new Date(iso))
}

export function truncateHash(hash: string, len = 16): string {
  return hash.length > len ? `${hash.slice(0, len)}…` : hash
}

export function getRiskColor(level: Scan['riskLevel'] | undefined): string {
  switch (level) {
    case 'High': return 'text-red-400'
    case 'Medium': return 'text-amber-400'
    case 'Low': return 'text-emerald-400'
    default: return 'text-slate-400'
  }
}

export function getVerdictColor(verdict: Scan['verdict'] | undefined): string {
  return verdict === 'malicious' ? 'text-red-400' : 'text-emerald-400'
}

export function extractApiError(err: unknown, fallback = 'An unexpected error occurred'): string {
  if (!err || typeof err !== 'object') return fallback
  const e = err as Record<string, unknown>
  const data = (e.response as Record<string, unknown> | undefined)?.data as Record<string, unknown> | undefined
  if (typeof data?.error === 'string') return data.error
  if (typeof data?.message === 'string') return data.message
  if (typeof (e as { message?: unknown }).message === 'string') return (e as { message: string }).message
  return fallback
}
