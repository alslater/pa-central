// Scans page
import { useEffect, useState } from 'react'
import { api, Scan, Host, RepoScanResultWithName } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, ScanBadge, RepoScanStatusBadge, FindingsTable, Empty, timeAgo } from '@/components/ui'
import { ChevronDown, ChevronUp } from 'lucide-react'

type Tab = 'host' | 'repo'

export function Scans() {
  const [scans, setScans] = useState<Scan[]>([])
  const [hosts, setHosts] = useState<Record<number, Host>>({})
  const [repoResults, setRepoResults] = useState<RepoScanResultWithName[]>([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [expandedRepoId, setExpandedRepoId] = useState<number | null>(null)
  const [tab, setTab] = useState<Tab>('host')

  useEffect(() => {
    Promise.all([
      api.scans.list({}),
      api.hosts.list(),
      api.repoScans.allResults().catch(() => [] as typeof repoResults),
    ])
      .then(([s, h, rr]) => {
        setScans(s)
        setHosts(Object.fromEntries(h.map(host => [host.id, host])))
        setRepoResults(rr)
      })
      .finally(() => setLoading(false))
  }, [])

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'host', label: 'Host scans', count: scans.length },
    { id: 'repo', label: 'Repo scans', count: repoResults.length },
  ]

  return (
    <Shell>
      <PageHeader title="Scans" subtitle="Project scan results from across the fleet" />

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', padding: '0 28px', flexShrink: 0 }}>
        {tabs.map(t => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              padding: '10px 16px', fontSize: 13, fontWeight: 500,
              color: tab === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
              borderBottom: `2px solid ${tab === t.id ? 'hsl(var(--brand))' : 'transparent'}`,
              marginBottom: -1, display: 'flex', alignItems: 'center', gap: 6,
              transition: 'color var(--duration-fast)',
            }}
          >
            {t.label}
            {!loading && (
              <span style={{
                fontSize: 11, fontWeight: 600, padding: '1px 6px', borderRadius: 10,
                background: tab === t.id ? 'hsl(var(--brand)/0.15)' : 'var(--bg-raised)',
                color: tab === t.id ? 'hsl(var(--brand))' : 'var(--text-muted)',
              }}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      <div style={{ padding: '24px 28px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 32 }}>
        {loading ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div> : (
          <>
            {tab === 'host' && <section>
              {scans.length === 0 ? <Empty message="No host scan results yet." /> : (
                <Card>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)' }}>
                        {['Status', 'Project', 'Type', 'Findings', 'Host', 'Scanned', ''].map(h => (
                          <th key={h} style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map(s => {
                        const hasFindings = s.findings && s.findings.length > 0
                        const isExpanded = expandedId === s.id
                        return (
                          <>
                            <tr
                              key={s.id}
                              style={{ borderBottom: isExpanded ? undefined : '1px solid var(--border-subtle)', cursor: hasFindings ? 'pointer' : 'default' }}
                              onClick={() => hasFindings && setExpandedId(isExpanded ? null : s.id)}
                            >
                              <td style={{ padding: '10px 16px' }}><ScanBadge status={s.status} /></td>
                              <td style={{ padding: '10px 16px' }}>
                                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.project_path}</div>
                                {s.sources && s.sources.length > 0 && (
                                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                                    {s.sources.map(src => (
                                      <span key={src} style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'var(--bg-input)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{src}</span>
                                    ))}
                                  </div>
                                )}
                              </td>
                              <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--text-secondary)' }}>{s.scan_type}</td>
                              <td style={{ padding: '10px 16px', fontSize: 12, color: s.finding_count > 0 ? 'var(--warn)' : 'var(--ok)', fontWeight: 600 }}>{s.finding_count}</td>
                              <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--text-secondary)' }}>{hosts[s.host_id]?.name ?? `#${s.host_id}`}</td>
                              <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)' }}>{timeAgo(s.scanned_at)}</td>
                              <td style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>
                                {hasFindings && (isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                              </td>
                            </tr>
                            {isExpanded && hasFindings && (
                              <tr key={`${s.id}-findings`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                <td colSpan={7} style={{ background: 'var(--bg-raised)', padding: 0 }}>
                                  <FindingsTable findings={s.findings!} />
                                </td>
                              </tr>
                            )}
                          </>
                        )
                      })}
                    </tbody>
                  </table>
                </Card>
              )}
            </section>}

            {tab === 'repo' && <section>
              {repoResults.length === 0 ? <Empty message="No repo scan results yet." /> : (
                <Card>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)' }}>
                        {['Status', 'Scan', 'Trigger', 'Findings', 'Breach', 'Scanned', ''].map(h => (
                          <th key={h} style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {repoResults.map(r => {
                        const hasFindings = r.findings && r.findings.length > 0
                        const isExpanded = expandedRepoId === r.id
                        return (
                          <>
                            <tr
                              key={r.id}
                              style={{ borderBottom: isExpanded ? undefined : '1px solid var(--border-subtle)', cursor: hasFindings ? 'pointer' : 'default' }}
                              onClick={() => hasFindings && setExpandedRepoId(isExpanded ? null : r.id)}
                            >
                              <td style={{ padding: '10px 16px' }}><RepoScanStatusBadge status={r.status} /></td>
                              <td style={{ padding: '10px 16px' }}>
                                <div style={{ fontSize: 13, fontWeight: 600 }}>{r.scan_name}</div>
                                <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{r.scan_url}</div>
                                {r.sources && r.sources.length > 0 && (
                                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                                    {r.sources.map(src => (
                                      <span key={src} style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'var(--bg-input)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{src}</span>
                                    ))}
                                  </div>
                                )}
                              </td>
                              <td style={{ padding: '10px 16px', fontSize: 12, color: 'var(--text-secondary)' }}>{r.triggered_by}</td>
                              <td style={{ padding: '10px 16px', fontSize: 12, color: (r.finding_count ?? 0) > 0 ? 'var(--warn)' : 'var(--ok)', fontWeight: 600 }}>{r.finding_count ?? 0}</td>
                              <td style={{ padding: '10px 16px' }}>
                                {r.scan_breach_count > 0 ? (
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[12px] font-semibold bg-status-fail/12 text-status-fail-text">
                                    {r.scan_breach_count}
                                  </span>
                                ) : (
                                  <span className="text-muted-foreground">—</span>
                                )}
                              </td>
                              <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)' }}>{r.started_at ? timeAgo(r.started_at) : '—'}</td>
                              <td style={{ padding: '10px 16px', color: 'var(--text-muted)' }}>
                                {hasFindings && (isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                              </td>
                            </tr>
                            {isExpanded && hasFindings && (
                              <tr key={`${r.id}-findings`} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                <td colSpan={7} style={{ background: 'var(--bg-raised)', padding: 0 }}>
                                  <FindingsTable findings={r.findings!} />
                                </td>
                              </tr>
                            )}
                          </>
                        )
                      })}
                    </tbody>
                  </table>
                </Card>
              )}
            </section>}
          </>
        )}
      </div>
    </Shell>
  )
}
