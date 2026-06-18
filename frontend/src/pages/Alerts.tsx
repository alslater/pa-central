import { useEffect, useState } from 'react'
import { api, Alert, AlertSeverity } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, SeverityBadge, Button, Select, useToast, Empty, timeAgo } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { CheckCheck } from 'lucide-react'

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | ''>('')
  const [ackedFilter, setAckedFilter] = useState<'false' | 'true' | ''>('false')
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isOperator = user?.role === 'admin' || user?.role === 'operator'

  const load = () => {
    setLoading(true)
    api.alerts.list({
      severity: severityFilter || undefined,
      acknowledged: ackedFilter === '' ? undefined : ackedFilter === 'true',
      limit: 200,
    }).then(setAlerts).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [severityFilter, ackedFilter])

  const ack = async (id: number, val: boolean) => {
    try {
      await api.alerts.acknowledge(id, val)
      show(val ? 'Alert acknowledged' : 'Alert unacknowledged')
      load()
    } catch (e: any) {
      show(e.message, 'err')
    }
  }

  const ackAll = async () => {
    const ids = alerts.filter(a => !a.acknowledged).map(a => a.id)
    if (ids.length === 0) return
    try {
      await api.alerts.acknowledgeBulk(ids)
      show(`Acknowledged ${ids.length} alerts`)
    } catch (e: any) {
      show(e.message ?? 'Failed to acknowledge alerts', 'err')
    } finally {
      load()
    }
  }

  return (
    <Shell>
      <PageHeader
        title="Alerts"
        subtitle="Package-alert detections across your fleet"
        action={isOperator ? (
          <Button variant="secondary" onClick={ackAll}>
            <CheckCheck size={13} />Acknowledge all
          </Button>
        ) : undefined}
      />
      <div className="p-6 px-7 overflow-auto">
        {/* Filters */}
        <div className="flex gap-2.5 mb-4">
          <Select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as any)} className="min-w-[140px]">
            <option value="">All severities</option>
            {(['critical','high','medium','warning','low','info'] as AlertSeverity[]).map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </Select>
          <Select value={ackedFilter} onChange={e => setAckedFilter(e.target.value as any)} className="min-w-[160px]">
            <option value="">All</option>
            <option value="false">Unacknowledged</option>
            <option value="true">Acknowledged</option>
          </Select>
        </div>

        {loading ? (
          <div className="text-muted-foreground text-[13px]">Loading…</div>
        ) : alerts.length === 0 ? (
          <Empty message="No alerts match the current filters." />
        ) : (
          <Card>
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-border">
                  {['Severity', 'Package', 'Ecosystem', 'Kind', 'Advisory', 'Project', 'Host', 'When', ''].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id} className={`border-b border-border/50 ${a.acknowledged ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-2.5"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-4 py-2.5">
                      <div className="font-mono text-xs font-medium">{a.package_name}</div>
                      {a.package_version && (
                        <div className="font-mono text-[11px] text-muted-foreground">@{a.package_version}</div>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{a.ecosystem}</td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{a.kind}</td>
                    <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">{a.advisory_id || '—'}</td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground max-w-[160px] overflow-hidden text-ellipsis whitespace-nowrap">
                      {a.project_path || '—'}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">#{a.host_id}</td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground whitespace-nowrap">{timeAgo(a.received_at)}</td>
                    <td className="px-4 py-2.5">
                      {isOperator && (
                        <Button
                          variant={a.acknowledged ? 'ghost' : 'secondary'}
                          onClick={() => ack(a.id, !a.acknowledged)}
                          className="text-[11px] px-2.5 py-1"
                        >
                          {a.acknowledged ? 'Undo' : 'Ack'}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>
      {Toast}
    </Shell>
  )
}
