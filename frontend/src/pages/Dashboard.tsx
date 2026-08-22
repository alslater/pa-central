import { useEffect, useState } from 'react'
import { api, DashboardStats, ExposureHistory } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, SeverityBadge, timeAgo } from '@/components/ui'
import { ExposureChart } from '@/components/ExposureChart'
import { useAuth } from '@/hooks/useAuth'
import { Bell } from 'lucide-react'

function StatCard({ label, value, sub, colorClass }: {
  label: string; value: number; sub?: string; colorClass?: string
}) {
  return (
    <Card className="stat-card">
      <div className="stat-card-label">{label}</div>
      <div className={`stat-card-value${colorClass ? ` ${colorClass}` : ''}`}>
        {value}
      </div>
      {sub && <div className="stat-card-sub">{sub}</div>}
    </Card>
  )
}

export default function Dashboard() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [exposureHistory, setExposureHistory] = useState<ExposureHistory | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      api.dashboard.get(),
      isAdmin ? api.dashboard.exposureHistory().catch(() => null) : Promise.resolve(null),
    ])
      .then(([s, eh]) => { setStats(s); setExposureHistory(eh) })
      .catch(console.error)
      .finally(() => setLoading(false))
    const iv = setInterval(() => {
      api.dashboard.get().then(setStats).catch(() => {})
      if (isAdmin) api.dashboard.exposureHistory().then(setExposureHistory).catch(() => {})
    }, 30000)
    return () => clearInterval(iv)
  }, [isAdmin])

  return (
    <Shell>
      <PageHeader title="Dashboard" subtitle="Fleet-wide status at a glance" />
      <div className="page-content">
        {loading ? (
          <div className="loading-text">Loading…</div>
        ) : stats ? (
          <>
            {/* Stats grid */}
            <div className="stats-grid">
              <StatCard label="Total Hosts" value={stats.total_hosts} sub={`${stats.hosts_online} online`} />
              <StatCard label="Online" value={stats.hosts_online} colorClass="pass" />
              <StatCard label="Offline / Unknown" value={stats.hosts_offline} colorClass={stats.hosts_offline > 0 ? 'fail' : undefined} />
              <StatCard label="Unacked Alerts" value={stats.unacknowledged_alerts} colorClass={stats.unacknowledged_alerts > 0 ? 'warn' : undefined} />
              <StatCard label="Critical Alerts" value={stats.critical_alerts} colorClass={stats.critical_alerts > 0 ? 'crit' : undefined} />
            </div>

            {/* Repo scans with an outstanding finding, by severity */}
            {stats.outstanding_scans_by_severity && (
              <>
                <div className="text-style-caption mb-2">Repo scans with outstanding findings</div>
                <div className="severity-tiles-row">
                  {(['critical', 'high', 'medium', 'warning', 'low', 'info'] as const).map(sev => (
                    <Card key={sev} className="severity-tile">
                      <div className="severity-tile-badge">
                        <SeverityBadge severity={sev} />
                      </div>
                      <div className="severity-tile-count">
                        {stats.outstanding_scans_by_severity![sev]}
                      </div>
                    </Card>
                  ))}
                </div>
              </>
            )}

            {/* Exposure history */}
            {exposureHistory && exposureHistory.points.length > 0 && (
              <>
                <div className="text-style-caption mb-2">Exposure over time</div>
                <ExposureChart points={exposureHistory.points} />
              </>
            )}

            {/* Recent alerts */}
            <Card>
              <div className="card-header-row">
                <Bell size={14} color="hsl(var(--brand))" />
                <span className="card-header-title">Recent unacknowledged alerts</span>
              </div>
              {stats.recent_alerts.length === 0 ? (
                <div className="card-empty-msg">
                  No unacknowledged alerts — fleet is clean
                </div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr className="data-thead-tr">
                      {['Severity', 'Package', 'Ecosystem', 'Advisory', 'Host', 'When'].map(h => (
                        <th key={h} scope="col" className="data-th-sm">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recent_alerts.map(a => (
                      <tr key={a.id} className="data-tr">
                        <td className="data-td"><SeverityBadge severity={a.severity} /></td>
                        <td className="data-td-mono-12">
                          {a.package_name}{a.package_version ? `@${a.package_version}` : ''}
                        </td>
                        <td className="data-td-muted-12">{a.ecosystem}</td>
                        <td className="data-td-mono-muted-11">{a.advisory_id || '—'}</td>
                        <td className="data-td-muted-12">host #{a.host_id}</td>
                        <td className="data-td-muted-11">{timeAgo(a.received_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </>
        ) : (
          <div className="error-text">Failed to load dashboard</div>
        )}
      </div>
    </Shell>
  )
}
