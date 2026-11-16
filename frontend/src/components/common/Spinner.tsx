import { Loader2 } from 'lucide-react'

interface SpinnerProps {
  size?: number
  className?: string
  label?: string
}

export function Spinner({ size = 20, className = '', label = 'Loading…' }: SpinnerProps) {
  return (
    <span role="status" aria-label={label} className={`inline-flex items-center gap-2 text-slate-400 ${className}`}>
      <Loader2 size={size} className="animate-spin" />
      {label && <span className="text-sm">{label}</span>}
    </span>
  )
}

export function PageSpinner() {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <Spinner size={28} label="Loading…" />
    </div>
  )
}
