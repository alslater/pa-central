import { useEffect, useState } from 'react'
import { api, DashboardStats } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, SeverityBadge, timeAgo } from '@/components/ui'
import { Bell } from 'lucide-react'

function StatCard({ label, value, sub, color }: {
  label: string; value: number; sub?: string; color?: string
}) {
  return (
    <Card style={{ padding: '20px 24px' }}>
      <div style={{ color: 'var(--text-secondary)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
        {label}
      </div>
      <div style={{ fontSize: 32, fontWeight: 600, color: color || 'var(--text-primary)', letterSpacing: '-0.03em', lineHeight: 1 }}>
        {value}
      </div>
      {sub && <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 6 }}>{sub}</div>}
    </Card>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.dashboard.get().then(setStats).catch(console.error).finally(() => setLoading(false))
    const iv = setInterval(() => api.dashboard.get().then(setStats).catch(() => {}), 30000)
    return () => clearInterval(iv)
  }, [])

  return (
    <Shell>
      <PageHeader title="Dashboard" subtitle="Fleet-wide status at a glance" />
      <div style={{ padding: '24px 28px', overflow: 'auto' }}>
        {loading ? (
          <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>
        ) : stats ? (
          <>
            {/* Stats grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12, marginBottom: 28 }}>
              <StatCard label="Total Hosts" value={stats.total_hosts} sub={`${stats.hosts_online} online`} />
              <StatCard label="Online" value={stats.hosts_online} color="var(--ok)" />
              <StatCard label="Offline / Unknown" value={stats.hosts_offline} color={stats.hosts_offline > 0 ? 'var(--err)' : undefined} />
              <StatCard label="Unacked Alerts" value={stats.unacknowledged_alerts} color={stats.unacknowledged_alerts > 0 ? 'var(--warn)' : undefined} />
              <StatCard label="Critical" value={stats.critical_alerts} color={stats.critical_alerts > 0 ? 'var(--sev-critical)' : undefined} />
              <StatCard label="Scans w/ Findings" value={stats.scans_with_findings} color={stats.scans_with_findings > 0 ? 'var(--warn)' : undefined} />
            </div>

            {/* Recent alerts */}
            <Card>
              <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Bell size={14} color="var(--accent)" />
                <span style={{ fontWeight: 600, fontSize: 13 }}>Recent unacknowledged alerts</span>
              </div>
              {stats.recent_alerts.length === 0 ? (
                <div style={{ padding: '32px 20px', color: 'var(--text-muted)', fontSize: 13, textAlign: 'center' }}>
                  No unacknowledged alerts — fleet is clean
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['Severity', 'Package', 'Ecosystem', 'Advisory', 'Host', 'When'].map(h => (
                        <th key={h} style={{
                          textAlign: 'left', padding: '8px 16px',
                          fontSize: 11, color: 'var(--text-muted)',
                          fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em',
                        }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {stats.recent_alerts.map(a => (
                      <tr key={a.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '10px 16px' }}><SeverityBadge severity={a.severity} /></td>
                        <td style={{ padding: '10px 16px', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                          {a.package_name}{a.package_version ? `@${a.package_version}` : ''}
                        </td>
                        <td style={{ padding: '10px 16px', color: 'var(--text-secondary)', fontSize: 12 }}>{a.ecosystem}</td>
                        <td style={{ padding: '10px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>
                          {a.advisory_id || '—'}
                        </td>
                        <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--text-secondary)' }}>host #{a.host_id}</td>
                        <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)' }}>{timeAgo(a.received_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </>
        ) : (
          <div style={{ color: 'var(--err)', fontSize: 13 }}>Failed to load dashboard</div>
        )}
      </div>
    </Shell>
  )
}
