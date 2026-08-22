import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router'
import { api, Host, Alert, Scan, ConfigTemplate } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, StatusDot, SeverityBadge, ScanBadge, Button, Select, useToast, Empty, ScanDetailTabs, timeAgo } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { useRovingTabs } from '@/lib/hooks'
import { ArrowLeft, Bell, ScanSearch, Settings2 } from 'lucide-react'

type Tab = 'alerts' | 'scans' | 'config'

export default function HostDetail() {
  const { id } = useParams<{ id: string }>()
  const hostId = Number(id)
  const navigate = useNavigate()
  const [host, setHost] = useState<Host | null>(null)
  const [tab, setTab] = useState<Tab>('alerts')
  const TAB_IDS: readonly Tab[] = ['alerts', 'scans', 'config']
  // Track which panels have been visited so they mount (and fetch) lazily on
  // first activation, then remain in the DOM for correct aria-controls linkage.
  const [visited, setVisited] = useState<Set<Tab>>(new Set(['alerts']))
  const selectTab = useCallback((t: Tab) => { setTab(t); setVisited(v => { if (v.has(t)) return v; const n = new Set(v); n.add(t); return n }) }, [])
  const { tabRef, onKeyDown: onTabKeyDown } = useRovingTabs(TAB_IDS, tab, selectTab)
  const [loading, setLoading] = useState(true)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isOperator = user?.role === 'admin' || user?.role === 'operator'

  useEffect(() => {
    api.hosts.get(hostId).then(setHost).catch(() => navigate('/hosts')).finally(() => setLoading(false))
  }, [hostId, navigate])

  if (loading) return <Shell><div className="loading-text-padded">Loading…</div></Shell>
  if (!host) return null

  return (
    <Shell>
      <PageHeader
        title={host.name}
        subtitle={host.hostname || host.description || undefined}
        action={
          <Button variant="ghost" onClick={() => navigate('/hosts')}>
            <ArrowLeft size={13} />All hosts
          </Button>
        }
      />

      {/* Host meta bar */}
      <div className="host-meta-bar">
        <div className="status-dot-wrap">
          <StatusDot status={host.daemon_status} />
        </div>
        {host.pa_version && (
          <span className="text-secondary">
            pa <span className="font-mono">{host.pa_version}</span>
          </span>
        )}
        {host.daemon_uptime_seconds != null && (
          <span className="text-secondary">
            up {Math.floor(host.daemon_uptime_seconds / 3600)}h
          </span>
        )}
        {host.last_seen_at && (
          <span className="text-muted">last seen {timeAgo(host.last_seen_at)}</span>
        )}
        {(host.tags || []).map(t => (
          <span key={t} className="host-tag">{t}</span>
        ))}
      </div>

      {/* Tabs */}
      <div className="tab-bar-surface" role="tablist">
        {([
          ['alerts', 'Alerts', Bell],
          ['scans', 'Scans', ScanSearch],
          ['config', 'Config', Settings2],
        ] as [Tab, string, any][]).map(([t, label, Icon]) => {
          const isActive = tab === t
          return (
            <button
              key={t}
              ref={tabRef(t)}
              type="button"
              role="tab"
              aria-selected={isActive}
              aria-controls={`host-panel-${t}`}
              id={`host-tab-${t}`}
              tabIndex={isActive ? 0 : -1}
              onClick={() => selectTab(t)}
              onKeyDown={onTabKeyDown}
              className={isActive ? 'tab-btn-accent active' : 'tab-btn-accent'}
            >
              <Icon size={13} />{label}
            </button>
          )
        })}
      </div>

      <div className="page-content-flex-1">
        <section id="host-panel-alerts" role="tabpanel" aria-labelledby="host-tab-alerts" hidden={tab !== 'alerts'}>
          {visited.has('alerts') && <HostAlerts hostId={hostId} isOperator={isOperator} show={show} />}
        </section>
        <section id="host-panel-scans" role="tabpanel" aria-labelledby="host-tab-scans" hidden={tab !== 'scans'}>
          {visited.has('scans') && <HostScans hostId={hostId} />}
        </section>
        <section id="host-panel-config" role="tabpanel" aria-labelledby="host-tab-config" hidden={tab !== 'config'}>
          {visited.has('config') && <HostConfig hostId={hostId} isOperator={isOperator} show={show} />}
        </section>
      </div>
      {Toast}
    </Shell>
  )
}

// ── Per-host alerts ───────────────────────────────────────────────────────────

function HostAlerts({ hostId, isOperator, show }: { hostId: number; isOperator: boolean; show: (m: string, k?: 'ok' | 'err') => void }) {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(() => {
    setLoading(true)
    api.alerts.list({ host_id: hostId, limit: 200 }).then(setAlerts).finally(() => setLoading(false))
  }, [hostId])
  useEffect(() => { load() }, [load]) // eslint-disable-line react-hooks/set-state-in-effect

  const ack = async (id: number, val: boolean) => {
    await api.alerts.acknowledge(id, val)
    show(val ? 'Acknowledged' : 'Unacknowledged')
    load()
  }

  if (loading) return <div className="loading-text">Loading…</div>
  if (!alerts.length) return <Empty message="No alerts from this host." />

  return (
    <Card>
      <table className="data-table">
        <thead>
          <tr className="data-thead-tr">
            {['Severity', 'Package', 'Kind', 'Advisory', 'Project', 'When'].map(h => (
              <th key={h} scope="col" className="data-th">{h}</th>
            ))}
            <th scope="col" className="data-th"><span className="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {alerts.map(a => (
            <tr key={a.id} className={`data-tr${a.acknowledged ? ' acknowledged' : ''}`}>
              <td className="data-td"><SeverityBadge severity={a.severity} /></td>
              <td className="data-td">
                <div className="host-alert-pkg-name">{a.package_name}</div>
                {a.package_version && <div className="host-alert-pkg-ver">@{a.package_version}</div>}
              </td>
              <td className="host-alert-kind">{a.kind}</td>
              <td className="host-alert-advisory">{a.advisory_id || '—'}</td>
              <td className="host-alert-path">{a.project_path || '—'}</td>
              <td className="host-alert-when">{timeAgo(a.received_at)}</td>
              <td className="data-td">
                {isOperator && (
                  <Button variant="ghost" onClick={() => ack(a.id, !a.acknowledged)} className="text-[11px] px-[10px] py-[4px]">
                    {a.acknowledged ? 'Undo' : 'Ack'}
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}

// ── Per-host scans ────────────────────────────────────────────────────────────

function HostScans({ hostId }: { hostId: number }) {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => { api.scans.list({ host_id: hostId }).then(setScans).finally(() => setLoading(false)) }, [hostId])

  if (loading) return <div className="loading-text">Loading…</div>
  if (!scans.length) return <Empty message="No scans from this host." />

  // Group by project_path, keeping only the row with the most recent scanned_at
  // per project — the host-agent surface has no lifecycle tracking, so we only
  // ever want to show the latest state of each project, not every historical scan.
  const latestByProject = new Map<string, Scan>()
  for (const s of scans) {
    const existing = latestByProject.get(s.project_path)
    if (!existing || new Date(s.scanned_at).getTime() > new Date(existing.scanned_at).getTime()) {
      latestByProject.set(s.project_path, s)
    }
  }
  const projects = [...latestByProject.values()].sort((a, b) => a.project_path.localeCompare(b.project_path))

  return (
    <div className="host-scans-list">
      {projects.map(s => {
        const hasFindings = !!s.findings?.length
        const hasRisks = !!s.risks?.length
        const hasRiskFailures = (s.risk_failures ?? 0) > 0
        const hasDetail = hasFindings || hasRisks
        const isExpanded = expanded === s.project_path
        return (
        <Card key={s.project_path}>
          <div
            className={`host-scan-card-row ${hasDetail ? 'data-tr-clickable' : 'data-tr-static'}`}
            onClick={hasDetail ? () => setExpanded(isExpanded ? null : s.project_path) : undefined}
            onKeyDown={hasDetail ? (e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(isExpanded ? null : s.project_path) } }) : undefined}
            role={hasDetail ? 'button' : undefined}
            tabIndex={hasDetail ? 0 : undefined}
            aria-expanded={hasDetail ? isExpanded : undefined}
          >
            <ScanBadge status={s.status} />
            <div className="host-scan-info">
              <div className="project-path-cell">{s.project_path}</div>
              {s.sources && s.sources.length > 0 && (
                <div className="sources-row">
                  {s.sources.map(src => (
                    <span key={src} className="source-tag">{src}</span>
                  ))}
                </div>
              )}
            </div>
            <span className="host-scan-type">{s.scan_type}</span>
            <span className={`host-scan-count ${s.finding_count > 0 ? 'has-findings' : 'no-findings'}`}>
              {s.finding_count} finding{s.finding_count !== 1 ? 's' : ''}
            </span>
            {s.risks == null ? (
              <span
                className="host-scan-count no-findings"
                title="No risk pass was reported for this scan — risk status is unknown, not clean"
              >
                risks unavailable
              </span>
            ) : (
              <span className={`host-scan-count ${hasRisks ? 'has-findings' : 'no-findings'}`}>
                {s.risks.length} risk{s.risks.length !== 1 ? 's' : ''}
              </span>
            )}
            {hasRiskFailures && (
              <span
                className="host-scan-count has-findings"
                title={`Risk scoring was unavailable for ${s.risk_failures} package(s) — an empty or short risk list may not mean the scan is clean`}
              >
                ⚠ {s.risk_failures} unscored
              </span>
            )}
            <span className="host-scan-when">{timeAgo(s.scanned_at)}</span>
          </div>
          {isExpanded && hasDetail && (
            <div className="host-scan-findings-panel">
              <ScanDetailTabs findings={s.findings} risks={s.risks} />
            </div>
          )}
        </Card>
        )
      })}
    </div>
  )
}

// ── Per-host config ───────────────────────────────────────────────────────────

function HostConfig({ hostId, isOperator, show }: { hostId: number; isOperator: boolean; show: (m: string, k?: 'ok' | 'err') => void }) {
  const [templates, setTemplates] = useState<ConfigTemplate[]>([])
  const [assigned, setAssigned] = useState<ConfigTemplate | null>(null)
  const [selected, setSelected] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    Promise.all([
      api.configs.list(),
      api.configs.forHost(hostId),
    ]).then(([all, current]) => {
      setTemplates(all)
      setAssigned(current)
      if (current) setSelected(String(current.id))
    }).finally(() => setLoading(false))
  }, [hostId])

  const assign = async () => {
    if (!selected) return
    setSaving(true)
    await api.configs.assign(Number(selected), hostId).catch(e => show(e.message, 'err'))
    const updated = await api.configs.forHost(hostId)
    setAssigned(updated)
    show('Config assigned')
    setSaving(false)
  }

  if (loading) return <div className="loading-text">Loading…</div>

  return (
    <div className="host-config-layout">
      <Card className="card-padded-20">
        <div className="host-config-header-section">
          <div className="host-config-section-title">Assigned config template</div>
          <div className="host-config-desc">
            The agent polls <code className="inline-code">GET /api/ingest/config</code> to download this as its config.toml.
          </div>
        </div>
        <div className="host-config-controls">
          <Select
            label="Template"
            value={selected}
            onChange={e => setSelected(e.target.value)}
            className="select-flex"
            disabled={!isOperator}
          >
            <option value="">No config assigned</option>
            {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
          </Select>
          {isOperator && (
            <Button variant="primary" onClick={assign} disabled={!selected || saving}>
              {saving ? 'Saving…' : 'Assign'}
            </Button>
          )}
        </div>
      </Card>

      {assigned && (
        <Card>
          <div className="host-config-assigned-bar">
            Currently assigned: <strong className="host-config-assigned-name">{assigned.name}</strong>
            {assigned.description && ` — ${assigned.description}`}
          </div>
          <pre className="host-config-toml-pre">
            {assigned.toml_content}
          </pre>
        </Card>
      )}
    </div>
  )
}
