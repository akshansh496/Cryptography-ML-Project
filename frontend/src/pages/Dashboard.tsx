import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  ShieldCheck, ShieldAlert, FileSearch, Zap,
  TrendingUp, Upload, ArrowRight
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts'
import { getScans, Scan } from '../services/scanService'
import { useAuth } from '../context/AuthContext'
import { PageSpinner } from '../components/common/Spinner'
import { Alert } from '../components/common/Alert'
import { VerdictBadge, RiskBadge } from '../components/common/Badges'
import { formatDate, extractApiError } from '../utils/format'

interface Stats {
  total: number
  malicious: number
  benign: number
  highRisk: number
  recentScans: Scan[]
  byDay: { date: string; benign: number; malicious: number }[]
  riskDist: { name: string; value: number; color: string }[]
}

function computeStats(scans: Scan[]): Stats {
  const malicious = scans.filter((s) => s.verdict === 'malicious').length
  const benign = scans.filter((s) => s.verdict === 'benign').length
  const highRisk = scans.filter((s) => s.riskLevel === 'High').length

  // Group last 7 days
  const dayMap: Record<string, { benign: number; malicious: number }> = {}
  const now = Date.now()
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 86400000)
    const key = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    dayMap[key] = { benign: 0, malicious: 0 }
  }
  scans.forEach((s) => {
    const key = new Date(s.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    if (dayMap[key]) dayMap[key][s.verdict]++
  })
  const byDay = Object.entries(dayMap).map(([date, v]) => ({ date, ...v }))

  const riskDist = [
    { name: 'Low Risk', value: scans.filter((s) => s.riskLevel === 'Low').length, color: '#10b981' },
    { name: 'Medium Risk', value: scans.filter((s) => s.riskLevel === 'Medium').length, color: '#f59e0b' },
    { name: 'High Risk', value: scans.filter((s) => s.riskLevel === 'High').length, color: '#ef4444' },
  ]

  return {
    total: scans.length,
    malicious,
    benign,
    highRisk,
    recentScans: scans.slice(0, 5),
    byDay,
    riskDist,
  }
}

const STAT_CARDS = (s: Stats) => [
  {
    label: 'Total Scans',
    value: s.total,
    icon: FileSearch,
    color: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/20',
  },
  {
    label: 'Malicious Detected',
    value: s.malicious,
    icon: ShieldAlert,
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
  },
  {
    label: 'Benign Files',
    value: s.benign,
    icon: ShieldCheck,
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/20',
  },
  {
    label: 'High-Risk Files',
    value: s.highRisk,
    icon: Zap,
    color: 'text-amber-400',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/20',
  },
]

const tooltipStyle = {
  backgroundColor: '#0a1628',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '8px',
  color: '#e2e8f0',
  fontSize: '12px',
}

export default function Dashboard() {
  const { user } = useAuth()
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getScans({ page: 1, limit: 100, sortBy: 'createdAt', order: 'desc' })
      .then((res) => setStats(computeStats(res.items)))
      .catch((err) => setError(extractApiError(err, 'Failed to load dashboard data')))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <PageSpinner />

  return (
    <div className="space-y-6 animate-slide-up">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-slate-500 text-sm mt-0.5">
            Welcome back, <span className="text-slate-300">{user?.email}</span>
          </p>
        </div>
        <Link to="/scanner" className="btn-primary self-start sm:self-auto">
          <Upload size={16} />
          Scan a File
        </Link>
      </div>

      {error && <Alert variant="error" message={error} onDismiss={() => setError(null)} />}

      {/* Stat cards */}
      {stats && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {STAT_CARDS(stats).map(({ label, value, icon: Icon, color, bg, border }) => (
              <div key={label} className={`stat-card border ${border}`}>
                <div className={`w-9 h-9 rounded-lg ${bg} flex items-center justify-center`}>
                  <Icon size={18} className={color} />
                </div>
                <div>
                  <p className="text-2xl font-bold text-white">{value}</p>
                  <p className="text-xs text-slate-500">{label}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Area chart – threat timeline */}
            <div className="card p-5 lg:col-span-2">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp size={16} className="text-blue-400" />
                <h3 className="text-sm font-semibold text-white">Threat Detection (Last 7 Days)</h3>
              </div>
              {stats.total === 0 ? (
                <EmptyChart />
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <AreaChart data={stats.byDay} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                    <defs>
                      <linearGradient id="benignGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="malGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area type="monotone" dataKey="benign" stroke="#10b981" fill="url(#benignGrad)" strokeWidth={2} name="Benign" />
                    <Area type="monotone" dataKey="malicious" stroke="#ef4444" fill="url(#malGrad)" strokeWidth={2} name="Malicious" />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>

            {/* Pie – risk distribution */}
            <div className="card p-5">
              <h3 className="text-sm font-semibold text-white mb-4">Risk Distribution</h3>
              {stats.total === 0 ? (
                <EmptyChart />
              ) : (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={stats.riskDist.filter((d) => d.value > 0)}
                      cx="50%"
                      cy="45%"
                      innerRadius={50}
                      outerRadius={70}
                      paddingAngle={3}
                      dataKey="value"
                    >
                      {stats.riskDist.map((entry) => (
                        <Cell key={entry.name} fill={entry.color} opacity={0.85} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                    <Legend iconSize={8} iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Bar chart – risk score distribution */}
          {stats.total > 0 && (
            <div className="card p-5">
              <h3 className="text-sm font-semibold text-white mb-4">Recent Scan Risk Scores</h3>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart
                  data={stats.recentScans.map((s) => ({ name: s.filename.slice(0, 16), score: s.riskScore }))}
                  margin={{ top: 4, right: 4, bottom: 20, left: -20 }}
                >
                  <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} angle={-20} textAnchor="end" />
                  <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]} name="Risk Score">
                    {stats.recentScans.map((s) => (
                      <Cell
                        key={s.id}
                        fill={s.riskLevel === 'High' ? '#ef4444' : s.riskLevel === 'Medium' ? '#f59e0b' : '#10b981'}
                        opacity={0.8}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Recent scans table */}
          <div className="card overflow-hidden">
            <div className="flex items-center justify-between p-5 border-b border-white/5">
              <h3 className="text-sm font-semibold text-white">Recent Scans</h3>
              <Link to="/scans" className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                View all <ArrowRight size={12} />
              </Link>
            </div>

            {stats.recentScans.length === 0 ? (
              <div className="p-10 text-center text-slate-500 text-sm">
                No scans yet.{' '}
                <Link to="/scanner" className="text-blue-400 hover:underline">Upload your first file</Link>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/5 text-xs text-slate-500">
                      <th className="text-left px-5 py-3 font-medium">File</th>
                      <th className="text-left px-5 py-3 font-medium">Verdict</th>
                      <th className="text-left px-5 py-3 font-medium">Risk</th>
                      <th className="text-left px-5 py-3 font-medium">Score</th>
                      <th className="text-left px-5 py-3 font-medium">Date</th>
                      <th className="px-5 py-3"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recentScans.map((scan) => (
                      <tr key={scan.id} className="table-row">
                        <td className="px-5 py-3 font-mono text-xs text-slate-300 max-w-[180px] truncate">
                          {scan.filename}
                        </td>
                        <td className="px-5 py-3"><VerdictBadge verdict={scan.verdict} /></td>
                        <td className="px-5 py-3"><RiskBadge level={scan.riskLevel} /></td>
                        <td className="px-5 py-3 font-mono text-xs text-slate-400">{scan.riskScore}/100</td>
                        <td className="px-5 py-3 text-xs text-slate-500">{formatDate(scan.createdAt)}</td>
                        <td className="px-5 py-3">
                          <Link to={`/scans/${scan.id}`} className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
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
        </>
      )}
    </div>
  )
}

function EmptyChart() {
  return (
    <div className="h-[200px] flex items-center justify-center text-slate-600 text-sm">
      No scan data yet
    </div>
  )
}


