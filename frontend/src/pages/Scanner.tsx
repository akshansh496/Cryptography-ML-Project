import { useState, useCallback, useRef, DragEvent, ChangeEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Upload, FileCode2, X, Zap, AlertTriangle, CheckCircle2, Shield
} from 'lucide-react'
import { uploadFile } from '../services/scanService'
import { Alert } from '../components/common/Alert'
import { Spinner } from '../components/common/Spinner'
import { formatFileSize, extractApiError } from '../utils/format'

type Stage = 'idle' | 'uploading' | 'analyzing' | 'done' | 'error'

const ALLOWED_EXT = ['.exe', '.dll']

function validateFile(file: File): string | null {
  const lower = file.name.toLowerCase()
  if (!ALLOWED_EXT.some((ext) => lower.endsWith(ext))) {
    return `Only .exe and .dll files are allowed. Got: ${file.name}`
  }
  if (file.size === 0) return 'File is empty.'
  if (file.size > 50 * 1024 * 1024) return 'File exceeds the 50 MB limit.'
  return null
}

export default function Scanner() {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)

  const [file, setFile] = useState<File | null>(null)
  const [stage, setStage] = useState<Stage>('idle')
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)

  const selectFile = useCallback((f: File) => {
    const err = validateFile(f)
    if (err) { setError(err); return }
    setFile(f)
    setError(null)
  }, [])

  const onDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) selectFile(f)
  }, [selectFile])

  const onChange = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) selectFile(f)
    e.target.value = ''
  }

  async function handleScan() {
    if (!file || stage === 'uploading' || stage === 'analyzing') return
    setError(null)
    setStage('uploading')
    setProgress(0)

    try {
      setStage('analyzing')
      const scan = await uploadFile(file, (pct) => {
        setProgress(pct)
        if (pct >= 100) setStage('analyzing')
      })
      setStage('done')
      navigate(`/scans/${scan.id}`, { state: { scan, fresh: true } })
    } catch (err) {
      setStage('error')
      setError(extractApiError(err, 'Scan failed. Please try again.'))
    }
  }

  const reset = () => {
    setFile(null)
    setStage('idle')
    setProgress(0)
    setError(null)
  }

  const busy = stage === 'uploading' || stage === 'analyzing'

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-slide-up">
      <div>
        <h1 className="text-2xl font-bold text-white">File Scanner</h1>
        <p className="text-slate-500 text-sm mt-1">
          Upload a Windows executable or DLL for AI-powered malware analysis
        </p>
      </div>

      {/* Security notice */}
      <div className="flex items-start gap-3 p-4 rounded-xl bg-blue-500/8 border border-blue-500/20 text-sm text-blue-300">
        <Shield size={16} className="mt-0.5 shrink-0 text-blue-400" />
        <div>
          <p className="font-semibold mb-0.5">Secure Analysis</p>
          <p className="text-blue-400/80 text-xs">
            Files are analyzed server-side by the EMBER Random Forest model. The original file is AES-256-GCM encrypted at rest and never executed.
          </p>
        </div>
      </div>

      {error && <Alert variant="error" message={error} onDismiss={() => { setError(null); if (stage === 'error') setStage('idle') }} />}

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !file && !busy && inputRef.current?.click()}
        className={`
          relative border-2 border-dashed rounded-2xl transition-all duration-200 cursor-pointer
          ${busy ? 'cursor-not-allowed opacity-80' : ''}
          ${dragging ? 'border-blue-500/60 bg-blue-500/8' : 'border-white/15 hover:border-white/25 bg-white/2 hover:bg-white/4'}
          ${file ? 'cursor-default' : ''}
        `}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".exe,.dll"
          className="hidden"
          onChange={onChange}
          disabled={busy}
        />

        <div className="p-10 flex flex-col items-center justify-center gap-4 text-center min-h-[220px]">
          {stage === 'idle' && !file && (
            <>
              <div className="w-14 h-14 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center">
                <Upload size={24} className="text-slate-400" />
              </div>
              <div>
                <p className="text-slate-200 font-medium">Drop your file here</p>
                <p className="text-slate-500 text-sm mt-1">or click to browse</p>
                <p className="text-slate-600 text-xs mt-2">.exe and .dll · Max 50 MB</p>
              </div>
            </>
          )}

          {file && stage === 'idle' && (
            <div className="w-full flex items-center gap-4 p-4 rounded-xl glass">
              <div className="w-10 h-10 rounded-lg bg-blue-500/15 border border-blue-500/25 flex items-center justify-center shrink-0">
                <FileCode2 size={20} className="text-blue-400" />
              </div>
              <div className="flex-1 text-left min-w-0">
                <p className="text-sm font-medium text-slate-200 truncate">{file.name}</p>
                <p className="text-xs text-slate-500 mt-0.5">{formatFileSize(file.size)}</p>
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); reset() }}
                className="text-slate-500 hover:text-red-400 transition-colors"
              >
                <X size={18} />
              </button>
            </div>
          )}

          {stage === 'uploading' && (
            <div className="w-full space-y-3">
              <div className="flex items-center gap-3">
                <Upload size={20} className="text-blue-400 animate-bounce shrink-0" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-slate-200">Uploading…</p>
                  <p className="text-xs text-slate-500">{file?.name}</p>
                </div>
                <span className="text-sm text-blue-400 font-mono">{progress}%</span>
              </div>
              <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-blue-500 to-violet-500 rounded-full transition-all duration-300"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}

          {stage === 'analyzing' && (
            <div className="space-y-3 w-full">
              <div className="flex items-center gap-3">
                <Zap size={20} className="text-violet-400 animate-pulse shrink-0" />
                <div className="flex-1 text-left">
                  <p className="text-sm font-medium text-slate-200">AI Analysis in progress…</p>
                  <p className="text-xs text-slate-500">EMBER Random Forest model is scanning {file?.name}</p>
                </div>
              </div>
              <div className="flex gap-1">
                {[...Array(8)].map((_, i) => (
                  <div
                    key={i}
                    className="h-1.5 flex-1 rounded-full bg-violet-500/40 animate-pulse-slow"
                    style={{ animationDelay: `${i * 0.15}s` }}
                  />
                ))}
              </div>
            </div>
          )}

          {stage === 'done' && (
            <div className="flex items-center gap-3 text-emerald-400">
              <CheckCircle2 size={24} />
              <p className="text-sm font-medium">Analysis complete — redirecting…</p>
            </div>
          )}

          {stage === 'error' && (
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle size={24} />
              <p className="text-sm font-medium">Scan failed</p>
            </div>
          )}
        </div>
      </div>

      {/* Action button */}
      <div className="flex gap-3">
        {file && stage === 'idle' && (
          <>
            <button onClick={handleScan} className="btn-primary flex-1 justify-center py-3 text-base">
              <Zap size={18} />
              Analyze File
            </button>
            <button onClick={reset} className="btn-secondary">
              <X size={16} />
              Clear
            </button>
          </>
        )}

        {!file && stage !== 'uploading' && stage !== 'analyzing' && (
          <button
            onClick={() => inputRef.current?.click()}
            className="btn-secondary w-full justify-center py-3"
          >
            <Upload size={16} />
            Browse Files
          </button>
        )}

        {busy && (
          <div className="w-full flex items-center justify-center py-3">
            <Spinner size={18} label={stage === 'uploading' ? 'Uploading…' : 'Analyzing with AI…'} />
          </div>
        )}
      </div>

      {/* Guidelines */}
      <div className="card p-4 space-y-2 text-xs text-slate-500">
        <p className="font-semibold text-slate-400">What to expect</p>
        <ul className="space-y-1 list-disc list-inside">
          <li>Only Windows PE executables (.exe, .dll) are accepted</li>
          <li>The file is validated for PE structure before analysis</li>
          <li>Analysis uses the EMBER 2018 Random Forest model</li>
          <li>Results include verdict, probability, risk score, and feature explanation</li>
          <li>Your file is AES-256-GCM encrypted and securely stored after analysis</li>
          <li>A benign result is not a guarantee of safety</li>
        </ul>
      </div>
    </div>
  )
}
