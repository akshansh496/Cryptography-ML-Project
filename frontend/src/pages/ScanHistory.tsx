import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Search, ArrowUpDown, ChevronLeft, ChevronRight, ArrowRight, Filter } from 'lucide-react'
import { getScans, Scan, SortBy, SortOrder } from '../services/scanService'
import { PageSpinner } from '../components/common/Spinner'
import { Alert } from '../components/common/Alert'
import { VerdictBadge, RiskBadge } from '../components/common/Badges'
import { formatDate, formatFileSize, extractApiError } from '../utils/format'

type VerdictFilter = 'all' | 'benign' | 'malicious'
type RiskFilter = 'all' | 'Low' | 'Medium' | 'High'

export default function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([])
  const [total, setTotal] = useState(0)
  const [totalPages, setTotalPages] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState<SortBy>('createdAt')
  const [order, setOrder] = useState<SortOrder>('desc')
  const [search, setSearch] = useState('')
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>('all')
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all')

  const LIMIT = 20

  const fetchScans = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await getScans({ page, limit: LIMIT, sortBy, order })
      setScans(res.items)
      setTotal(res.total)
      setTotalPages(res.totalPages)
    } catch (err) {
      setError(extractApiError(err, 'Failed to load scan history'))
    } finally {
      setLoading(false)
    }
  }, [page, sortBy, order])

  useEffect(() => { fetchScans() }, [fetchScans])

  // Client-side filtering (search, verdict, risk)
  const filtered = scans.filter((s) => {
    const matchSearch = !search || s.filename.toLowerCase().includes(search.toLowerCase())
    const matchVerdict = verdictFilter === 'all' || s.verdict === verdictFilter
    const matchRisk = riskFilter === 'all' || s.riskLevel === riskFilter
    return matchSearch && matchVerdict && matchRisk
  })

  function toggleSort(col: SortBy) {
    if (sortBy === col) setOrder((o) => (o === 'desc' ? 'asc' : 'desc'))
    else { setSortBy(col); setOrder('desc') }
    setPage(1)
  }

  return (
    <div className="space-y-5 animate-slide-up">
      <div>
        <h1 className="text-2xl font-bold text-white">Scan History</h1>
        <p className="text-slate-500 text-sm mt-0.5">{total} total scans</p>
      </div>

      {error && <Alert variant="error" message={error} onDismiss={() => setError(null)} />}

      {/* Filters */}
      <div className="card p-4 flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search by filename…"
            className="input-field pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="flex gap-2">
          <div className="relative">
            <Filter size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <select
              className="input-field pl-7 pr-3 py-2.5 text-xs appearance-none cursor-pointer min-w-[120px]"
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value as VerdictFilter)}
            >
              <option value="all">All Verdicts</option>
              <option value="benign">Benign</option>
              <option value="malicious">Malicious</option>
            </select>
          </div>

          <select
            className="input-field py-2.5 text-xs appearance-none cursor-pointer min-w-[110px]"
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as RiskFilter)}
          >
            <option value="all">All Risks</option>
            <option value="Low">Low Risk</option>
            <option value="Medium">Medium Risk</option>
            <option value="High">High Risk</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        {loading ? (
          <div className="p-10 flex justify-center">
            <PageSpinner />
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-10 text-center text-slate-500 text-sm">
            {total === 0 ? (
              <>No scans yet. <Link to="/scanner" className="text-blue-400 hover:underline">Upload your first file →</Link></>
            ) : (
              'No scans match your filters.'
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/5 text-xs text-slate-500">
                  <th className="text-left px-5 py-3 font-medium">File</th>
                  <th className="text-left px-5 py-3 font-medium">Verdict</th>
                  <th className="text-left px-5 py-3 font-medium">Risk Level</th>
                  <th className="text-left px-5 py-3 font-medium">
                    <button
                      onClick={() => toggleSort('riskScore')}
                      className="flex items-center gap-1 hover:text-slate-200 transition-colors"
                    >
                      Score <ArrowUpDown size={12} />
                    </button>
                  </th>
                  <th className="text-left px-5 py-3 font-medium">Size</th>
                  <th className="text-left px-5 py-3 font-medium">
                    <button
                      onClick={() => toggleSort('createdAt')}
                      className="flex items-center gap-1 hover:text-slate-200 transition-colors"
                    >
                      Date <ArrowUpDown size={12} />
                    </button>
                  </th>
                  <th className="px-5 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((scan) => (
                  <tr key={scan.id} className="table-row">
                    <td className="px-5 py-3">
                      <p className="font-mono text-xs text-slate-200 max-w-[200px] truncate">{scan.filename}</p>
                    </td>
                    <td className="px-5 py-3"><VerdictBadge verdict={scan.verdict} /></td>
                    <td className="px-5 py-3"><RiskBadge level={scan.riskLevel} /></td>
                    <td className="px-5 py-3">
                      <span className={`font-mono text-xs font-semibold ${
                        scan.riskLevel === 'High' ? 'text-red-400' :
                        scan.riskLevel === 'Medium' ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {scan.riskScore}/100
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-slate-500">{formatFileSize(scan.fileSize)}</td>
                    <td className="px-5 py-3 text-xs text-slate-500">{formatDate(scan.createdAt)}</td>
                    <td className="px-5 py-3">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 whitespace-nowrap transition-colors"
                      >
                        Details <ArrowRight size={12} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <p className="text-slate-500 text-xs">
            Page {page} of {totalPages} · {total} total
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setPage((p) => p - 1)}
              disabled={page <= 1 || loading}
              className="btn-secondary py-1.5 px-3"
            >
              <ChevronLeft size={15} />
              Prev
            </button>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={page >= totalPages || loading}
              className="btn-secondary py-1.5 px-3"
            >
              Next
              <ChevronRight size={15} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
