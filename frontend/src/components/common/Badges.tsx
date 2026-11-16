import type { Scan } from '../../services/scanService'
import { ShieldCheck, ShieldAlert, Minus } from 'lucide-react'

export function VerdictBadge({ verdict }: { verdict: Scan['verdict'] }) {
  if (verdict === 'malicious') {
    return (
      <span className="badge-malicious">
        <ShieldAlert size={12} />
        MALICIOUS
      </span>
    )
  }
  return (
    <span className="badge-benign">
      <ShieldCheck size={12} />
      BENIGN
    </span>
  )
}

export function RiskBadge({ level }: { level: Scan['riskLevel'] }) {
  if (level === 'High') return <span className="badge-high"><Minus size={10} />High Risk</span>
  if (level === 'Medium') return <span className="badge-medium"><Minus size={10} />Medium Risk</span>
  return <span className="badge-low"><Minus size={10} />Low Risk</span>
}
