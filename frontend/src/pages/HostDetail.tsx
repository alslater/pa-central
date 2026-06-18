import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api, Host, Alert, Scan, ConfigTemplate } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, StatusDot, SeverityBadge, ScanBadge, Button, Select, useToast, Empty, FindingsTable, timeAgo } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { ArrowLeft, Bell, ScanSearch, Settings2 } from 'lucide-react'

type Tab = 'alerts' | 'scans' | 'config'

export default function HostDetail() {
  const { id } = useParams<{ id: string }>()
  const hostId = Number(id)
  const navigate = useNavigate()
  const [host, setHost] = useState<Host | null>(null)
  const [tab, setTab] = useState<Tab>('alerts')
  const [loading, setLoading] = useState(true)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isOperator = user?.role === 'admin' || user?.role === 'operator'

  useEffect(() => {
    api.hosts.get(hostId).then(setHost).catch(() => navigate('/hosts')).finally(() => setLoading(false))
  }, [hostId])

  if (loading) return <Shell><div style={{ padding: 28, color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div></Shell>
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
      <div style={{
        display: 'flex', gap: 24, padding: '12px 28px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        fontSize: 12, flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <StatusDot status={host.daemon_status} />
        </div>
        {host.pa_version && (
          <span style={{ color: 'var(--text-secondary)' }}>
            pa <span style={{ fontFamily: 'var(--font-mono)' }}>{host.pa_version}</span>
          </span>
        )}
        {host.daemon_uptime_seconds != null && (
          <span style={{ color: 'var(--text-secondary)' }}>
            up {Math.floor(host.daemon_uptime_seconds / 3600)}h
          </span>
        )}
        {host.last_seen_at && (
          <span style={{ color: 'var(--text-muted)' }}>last seen {timeAgo(host.last_seen_at)}</span>
        )}
        {(host.tags || []).map(t => (
          <span key={t} style={{
            background: 'var(--bg-raised)', border: '1px solid var(--border)',
            padding: '1px 7px', borderRadius: 3, color: 'var(--text-secondary)',
          }}>{t}</span>
        ))}
      </div>

      {/* Tabs */}
      <div style={{
        display: 'flex', gap: 0,
        borderBottom: '1px solid var(--border)',
        padding: '0 28px',
        background: 'var(--bg-surface)',
      }}>
        {([
          ['alerts', 'Alerts', Bell],
          ['scans', 'Scans', ScanSearch],
          ['config', 'Config', Settings2],
        ] as [Tab, string, any][]).map(([t, label, Icon]) => (
          <button key={t} onClick={() => setTab(t)} style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '10px 16px', background: 'none', border: 'none',
            borderBottom: `2px solid ${tab === t ? 'var(--accent)' : 'transparent'}`,
            color: tab === t ? 'var(--accent)' : 'var(--text-secondary)',
            cursor: 'pointer', fontSize: 13, fontWeight: 500,
            marginBottom: -1, fontFamily: 'var(--font-ui)',
          }}>
            <Icon size={13} />{label}
          </button>
        ))}
      </div>

      <div style={{ padding: '24px 28px', overflow: 'auto', flex: 1 }}>
        {tab === 'alerts' && <HostAlerts hostId={hostId} isOperator={isOperator} show={show} />}
        {tab === 'scans' && <HostScans hostId={hostId} />}
        {tab === 'config' && <HostConfig hostId={hostId} isOperator={isOperator} show={show} />}
      </div>
      {Toast}
    </Shell>
  )
}

// ── Per-host alerts ───────────────────────────────────────────────────────────

function HostAlerts({ hostId, isOperator, show }: { hostId: number; isOperator: boolean; show: (m: string, k?: 'ok' | 'err') => void }) {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)

  const load = () => api.alerts.list({ host_id: hostId, limit: 200 }).then(setAlerts).finally(() => setLoading(false))
  useEffect(() => { load() }, [hostId])

  const ack = async (id: number, val: boolean) => {
    await api.alerts.acknowledge(id, val)
    show(val ? 'Acknowledged' : 'Unacknowledged')
    load()
  }

  if (loading) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>
  if (!alerts.length) return <Empty message="No alerts from this host." />

  return (
    <Card>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border)' }}>
            {['Severity', 'Package', 'Kind', 'Advisory', 'Project', 'When', ''].map(h => (
              <th key={h} style={{ textAlign: 'left', padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {alerts.map(a => (
            <tr key={a.id} style={{ borderBottom: '1px solid var(--border-subtle)', opacity: a.acknowledged ? 0.45 : 1 }}>
              <td style={{ padding: '10px 16px' }}><SeverityBadge severity={a.severity} /></td>
              <td style={{ padding: '10px 16px' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 500 }}>{a.package_name}</div>
                {a.package_version && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>@{a.package_version}</div>}
              </td>
              <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-secondary)' }}>{a.kind}</td>
              <td style={{ padding: '10px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>{a.advisory_id || '—'}</td>
              <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.project_path || '—'}</td>
              <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{timeAgo(a.received_at)}</td>
              <td style={{ padding: '10px 16px' }}>
                {isOperator && (
                  <Button variant="ghost" onClick={() => ack(a.id, !a.acknowledged)} style={{ fontSize: 11, padding: '4px 10px' }}>
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
  const [expanded, setExpanded] = useState<number | null>(null)

  useEffect(() => { api.scans.list({ host_id: hostId }).then(setScans).finally(() => setLoading(false)) }, [hostId])

  if (loading) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>
  if (!scans.length) return <Empty message="No scans from this host." />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {scans.map(s => (
        <Card key={s.id}>
          <div
            style={{ padding: '12px 16px', display: 'flex', gap: 16, alignItems: 'center', cursor: s.findings?.length ? 'pointer' : 'default' }}
            onClick={() => setExpanded(expanded === s.id ? null : s.id)}
          >
            <ScanBadge status={s.status} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.project_path}</div>
              {s.sources && s.sources.length > 0 && (
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                  {s.sources.map(src => (
                    <span key={src} style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: 'var(--bg-input)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{src}</span>
                  ))}
                </div>
              )}
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{s.scan_type}</span>
            <span style={{ fontSize: 12, fontWeight: 600, color: s.finding_count > 0 ? 'var(--warn)' : 'var(--ok)', minWidth: 60, textAlign: 'right' }}>
              {s.finding_count} finding{s.finding_count !== 1 ? 's' : ''}
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 80, textAlign: 'right' }}>{timeAgo(s.scanned_at)}</span>
          </div>
          {expanded === s.id && s.findings && s.findings.length > 0 && (
            <div style={{ borderTop: '1px solid var(--border)', background: 'var(--bg-raised)', borderRadius: '0 0 var(--radius-lg) var(--radius-lg)' }}>
              <FindingsTable findings={s.findings} />
            </div>
          )}
        </Card>
      ))}
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

  if (loading) return <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 700 }}>
      <Card style={{ padding: 20 }}>
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Assigned config template</div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
            The agent polls <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11, background: 'var(--bg-raised)', padding: '1px 5px', borderRadius: 3 }}>GET /api/ingest/config</code> to download this as its config.toml.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
          <Select
            label="Template"
            value={selected}
            onChange={e => setSelected(e.target.value)}
            style={{ flex: 1 }}
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
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', fontSize: 12, color: 'var(--text-secondary)' }}>
            Currently assigned: <strong style={{ color: 'var(--text-primary)' }}>{assigned.name}</strong>
            {assigned.description && ` — ${assigned.description}`}
          </div>
          <pre style={{
            margin: 0, padding: '14px 16px',
            fontFamily: 'var(--font-mono)', fontSize: 11,
            color: 'var(--text-secondary)', lineHeight: 1.7,
            overflow: 'auto', maxHeight: 400,
          }}>
            {assigned.toml_content}
          </pre>
        </Card>
      )}
    </div>
  )
}

