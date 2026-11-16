import { useState, useEffect } from 'react'
import { useParams, useLocation, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft, Download, Trash2, Shield, ShieldAlert,
  Copy, Check, AlertTriangle, Hash, FileCode2, Calendar,
  Cpu, ChevronDown, ChevronUp, Info
} from 'lucide-react'
import { getScan, deleteScan, downloadFile, Scan } from '../services/scanService'
import { PageSpinner, Spinner } from '../components/common/Spinner'
import { Alert } from '../components/common/Alert'
import { VerdictBadge, RiskBadge } from '../components/common/Badges'
import { formatDate, formatFileSize, extractApiError } from '../utils/format'
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts'

interface LocationState { scan?: Scan; fresh?: boolean }

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch { /* ignore */ }
  }
  return (
    <button onClick={copy} className="text-slate-500 hover:text-slate-300 transition-colors" title="Copy">
      {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
    </button>
  )
}

function RiskGauge({ score, level }: { score: number; level: Scan['riskLevel'] }) {
  const color = level === 'High' ? '#ef4444' : level === 'Medium' ? '#f59e0b' : '#10b981'
  const data = [{ name: 'score', value: score, fill: color }]
  return (
    <div className="relative w-32 h-32">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart cx="50%" cy="50%" innerRadius="65%" outerRadius="90%" data={data} startAngle={225} endAngle={-45}>
          <RadialBar dataKey="value" cornerRadius={6} background={{ fill: 'rgba(255,255,255,0.05)' }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-white">{score}</span>
        <span className="text-xs text-slate-500">/ 100</span>
      </div>
    </div>
  )
}

export default function ScanDetails() {
  const { id } = useParams<{ id: string }>()
  const location = useLocation()
  const navigate = useNavigate()
  const state = location.state as LocationState | null

  const [scan, setScan] = useState<Scan | null>(state?.scan ?? null)
  const [loading, setLoading] = useState(!scan)
  const [error, setError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)
  const [dlError, setDlError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [showFeatures, setShowFeatures] = useState(true)

  useEffect(() => {
    if (!scan && id) {
      getScan(id)
        .then(setScan)
        .catch((err) => setError(extractApiError(err, 'Failed to load scan details')))
        .finally(() => setLoading(false))
    }
  }, [id, scan])

  async function handleDownload() {
    if (!scan) return
    setDlError(null)
    setDownloading(true)
    try {
      await downloadFile(scan.id, scan.filename)
    } catch (err) {
      setDlError(extractApiError(err, 'Download failed. File integrity check may have failed.'))
    } finally {
      setDownloading(false)
    }
  }

  async function handleDelete() {
    if (!scan) return
    setDeleting(true)
    try {
      await deleteScan(scan.id)
      navigate('/scans', { replace: true })
    } catch (err) {
      setError(extractApiError(err, 'Failed to delete scan'))
      setDeleting(false)
      setConfirmDelete(false)
    }
  }

  if (loading) return <PageSpinner />
  if (error) return (
    <div className="max-w-2xl mx-auto space-y-4 animate-fade-in">
      <Link to="/scans" className="btn-secondary self-start"><ArrowLeft size={15} />Back</Link>
      <Alert variant="error" message={error} />
    </div>
  )
  if (!scan) return null

  const isMalicious = scan.verdict === 'malicious'
  const features = Array.isArray(scan.explanation) ? scan.explanation : []

  return (
    <div className="max-w-3xl mx-auto space-y-5 animate-slide-up">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <Link to="/scans" className="btn-secondary self-start">
          <ArrowLeft size={15} />Back
        </Link>
        <div className="flex-1">
          <h1 className="text-xl font-bold text-white truncate">{scan.filename}</h1>
          <p className="text-slate-500 text-xs">{formatDate(scan.createdAt)}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="btn-secondary"
          >
            {downloading ? <Spinner size={14} label="Downloading…" /> : <><Download size={15} />Download</>}
          </button>
          <button
            onClick={() => setConfirmDelete(true)}
            className="btn-danger"
            disabled={deleting}
          >
            {deleting ? <Spinner size={14} label="" /> : <><Trash2 size={15} />Delete</>}
          </button>
        </div>
      </div>

      {dlError && <Alert variant="error" message={dlError} onDismiss={() => setDlError(null)} />}

      {/* Duplicate notice */}
      {state?.fresh && (scan as Scan & { duplicate?: boolean }).duplicate && (
        <Alert variant="info" message="This file was previously scanned. The result above reflects the latest analysis." />
      )}

      {/* Fresh scan banner */}
      {state?.fresh && (
        <Alert
          variant={isMalicious ? 'error' : 'success'}
          title={isMalicious ? '⚠ Malware detected' : '✓ File appears benign'}
          message={isMalicious
            ? 'This file was classified as malicious. Do not execute it.'
            : 'No malware signature detected. This is not a guarantee of safety.'}
        />
      )}

      {/* Verdict hero */}
      <div className={`card p-6 border ${isMalicious ? 'border-red-500/25 bg-red-500/5' : 'border-emerald-500/20 bg-emerald-500/4'}`}>
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6">
          {/* Gauge */}
          <RiskGauge score={scan.riskScore} level={scan.riskLevel} />

          <div className="flex-1 space-y-3 text-center sm:text-left">
            <div className="flex flex-wrap justify-center sm:justify-start gap-2">
              <VerdictBadge verdict={scan.verdict} />
              <RiskBadge level={scan.riskLevel} />
            </div>

            <div>
              <p className="text-3xl font-bold text-white capitalize">{scan.verdict}</p>
              <p className="text-sm text-slate-400 mt-0.5">
                Malicious probability: <span className="font-semibold text-slate-200">{(scan.probability * 100).toFixed(1)}%</span>
              </p>
            </div>

            <div className="flex flex-wrap gap-4 justify-center sm:justify-start text-xs text-slate-500">
              <span className="flex items-center gap-1.5"><Cpu size={12} />Model: <code className="text-slate-300 font-mono">{scan.modelVersion}</code></span>
              <span className="flex items-center gap-1.5"><FileCode2 size={12} />{formatFileSize(scan.fileSize)}</span>
              <span className="flex items-center gap-1.5"><Calendar size={12} />{formatDate(scan.createdAt)}</span>
            </div>
          </div>

          <div className="text-center hidden sm:block">
            {isMalicious
              ? <ShieldAlert size={48} className="text-red-400 opacity-80" />
              : <Shield size={48} className="text-emerald-400 opacity-80" />}
          </div>
        </div>
      </div>

      {/* Metadata */}
      <div className="card p-5 space-y-3">
        <h2 className="text-sm font-semibold text-white">File Metadata</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          <MetaRow icon={<Hash size={13} />} label="SHA-256">
            <div className="flex items-center gap-2 min-w-0">
              <code className="font-mono text-xs text-slate-300 truncate">{scan.sha256}</code>
              <CopyButton text={scan.sha256} />
            </div>
          </MetaRow>
          <MetaRow icon={<FileCode2 size={13} />} label="Filename">
            <span className="font-mono text-xs text-slate-300">{scan.filename}</span>
          </MetaRow>
          <MetaRow icon={<FileCode2 size={13} />} label="File Size">
            <span className="text-slate-300">{formatFileSize(scan.fileSize)}</span>
          </MetaRow>
          <MetaRow icon={<Cpu size={13} />} label="Scan ID">
            <div className="flex items-center gap-2">
              <code className="font-mono text-xs text-slate-400 truncate">{scan.id}</code>
              <CopyButton text={scan.id} />
            </div>
          </MetaRow>
        </div>
      </div>

      {/* Feature explanation */}
      {features.length > 0 && (
        <div className="card overflow-hidden">
          <button
            onClick={() => setShowFeatures(!showFeatures)}
            className="w-full flex items-center justify-between p-5 hover:bg-white/3 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Info size={15} className="text-blue-400" />
              <h2 className="text-sm font-semibold text-white">Model Explanation ({features.length} features)</h2>
            </div>
            {showFeatures ? <ChevronUp size={16} className="text-slate-500" /> : <ChevronDown size={16} className="text-slate-500" />}
          </button>

          {showFeatures && (
            <div className="border-t border-white/5 p-5 space-y-3">
              <p className="text-xs text-slate-500">Top features contributing to this classification:</p>
              {features.map((f, i) => {
                const pct = Math.min(100, Math.round((f.contribution ?? f.importance ?? 0) * 100))
                return (
                  <div key={`${f.name}-${i}`} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono text-slate-300">{f.name}</span>
                      <span className="text-slate-500 font-mono">{pct}%</span>
                    </div>
                    {f.description && (
                      <p className="text-xs text-slate-600">{f.description}</p>
                    )}
                    <div className="h-1 bg-white/8 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{
                          width: `${pct}%`,
                          background: i === 0
                            ? 'linear-gradient(90deg, #3b82f6, #8b5cf6)'
                            : 'rgba(100,116,139,0.6)',
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* Security notice */}
      <div className="flex gap-3 p-4 rounded-xl bg-slate-800/40 border border-white/5 text-xs text-slate-500">
        <AlertTriangle size={14} className="shrink-0 mt-0.5 text-amber-500/60" />
        <p>
          This analysis is provided for informational purposes. A benign classification does not guarantee the file is safe.
          The downloaded file is decrypted on the server and verified against its original SHA-256 hash before delivery.
        </p>
      </div>

      {/* Delete confirm modal */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="card p-6 max-w-sm w-full shadow-2xl animate-slide-up space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                <Trash2 size={18} className="text-red-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Delete scan?</h3>
                <p className="text-xs text-slate-500">This cannot be undone</p>
              </div>
            </div>
            <p className="text-sm text-slate-400">
              The scan record and the encrypted file <span className="font-mono text-slate-200">{scan.filename}</span> will be permanently deleted.
            </p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setConfirmDelete(false)} className="btn-secondary">Cancel</button>
              <button onClick={handleDelete} disabled={deleting} className="btn-danger">
                {deleting ? <Spinner size={14} label="Deleting…" /> : <><Trash2 size={14} />Delete permanently</>}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function MetaRow({ icon, label, children }: { icon: React.ReactNode; label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-white/3">
      <span className="text-slate-500 mt-0.5 shrink-0">{icon}</span>
      <div className="min-w-0">
        <p className="text-xs text-slate-500 mb-0.5">{label}</p>
        <div className="min-w-0">{children}</div>
      </div>
    </div>
  )
}
