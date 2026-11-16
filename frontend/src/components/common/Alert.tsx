import { AlertTriangle, XCircle, Info, CheckCircle, X } from 'lucide-react'

type AlertVariant = 'error' | 'warning' | 'info' | 'success'

interface AlertProps {
  variant?: AlertVariant
  title?: string
  message: string
  onDismiss?: () => void
}

const styles: Record<AlertVariant, { wrapper: string; icon: JSX.Element }> = {
  error: {
    wrapper: 'bg-red-500/10 border-red-500/30 text-red-300',
    icon: <XCircle size={16} className="text-red-400 mt-0.5 shrink-0" />,
  },
  warning: {
    wrapper: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
    icon: <AlertTriangle size={16} className="text-amber-400 mt-0.5 shrink-0" />,
  },
  info: {
    wrapper: 'bg-blue-500/10 border-blue-500/30 text-blue-300',
    icon: <Info size={16} className="text-blue-400 mt-0.5 shrink-0" />,
  },
  success: {
    wrapper: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300',
    icon: <CheckCircle size={16} className="text-emerald-400 mt-0.5 shrink-0" />,
  },
}

export function Alert({ variant = 'error', title, message, onDismiss }: AlertProps) {
  const { wrapper, icon } = styles[variant]
  return (
    <div className={`flex items-start gap-3 p-3.5 rounded-lg border text-sm animate-fade-in ${wrapper}`} role="alert">
      {icon}
      <div className="flex-1 min-w-0">
        {title && <p className="font-semibold mb-0.5">{title}</p>}
        <p className="leading-relaxed">{message}</p>
      </div>
      {onDismiss && (
        <button onClick={onDismiss} className="shrink-0 opacity-70 hover:opacity-100 transition-opacity">
          <X size={14} />
        </button>
      )}
    </div>
  )
}
