import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, Host } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, StatusDot, Button, useToast, Empty, timeAgo } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { Trash2, Server } from 'lucide-react'

export default function Hosts() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [loading, setLoading] = useState(true)
  const { show, Toast } = useToast()
  const navigate = useNavigate()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const load = useCallback(() => {
    setLoading(true)
    api.hosts.list().then(setHosts).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }, [show])
  useEffect(() => { load() }, [load]) // eslint-disable-line react-hooks/set-state-in-effect

  const del = async (id: number, name: string) => {
    if (!confirm(`Delete host "${name}"?`)) return
    try {
      await api.hosts.delete(id)
      show('Host deleted')
      load()
    } catch (e: any) {
      show(e.message, 'err')
    }
  }

  return (
    <Shell>
      <PageHeader
        title="Hosts"
        subtitle={`${hosts.length} registered hosts — agents self-register on first heartbeat`}
      />
      <div className="p-6 px-7 overflow-auto">
        {loading ? (
          <div className="text-muted-foreground text-[13px]">Loading…</div>
        ) : hosts.length === 0 ? (
          <Empty message="No hosts registered yet. Add a host to get started." />
        ) : (
          <Card>
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-border">
                  {['Name', 'Hostname', 'Status', 'PA Version', 'Tags', 'Last seen'].map(h => (
                    <th key={h} scope="col" className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                  ))}
                  <th scope="col" className="px-4 py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {hosts.map(h => (
                  <tr key={h.id} className="border-b border-border/50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Server size={13} className="text-muted-foreground" />
                        <button type="button" onClick={() => navigate(`/hosts/${h.id}`)}
                          className="bg-transparent border-none cursor-pointer text-status-review font-medium p-0 text-[inherit]">
                          {h.name}
                        </button>
                      </div>
                      {h.description && (
                        <div className="text-[11px] text-muted-foreground mt-0.5 pl-[21px]">{h.description}</div>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{h.hostname || '—'}</td>
                    <td className="px-4 py-3"><StatusDot status={h.daemon_status} /></td>
                    <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground">{h.pa_version || '—'}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1 flex-wrap">
                        {(h.tags || []).map(t => (
                          <span key={t} className="bg-muted border border-border px-1.5 py-px rounded text-[11px] text-muted-foreground">
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[11px] text-muted-foreground">
                      {h.last_seen_at ? timeAgo(h.last_seen_at) : 'Never'}
                    </td>
                    <td className="px-4 py-3">
                      {isAdmin && (
                        <Button variant="ghost" onClick={() => del(h.id, h.name)} title={`Delete ${h.name}`} aria-label={`Delete ${h.name}`}>
                          <Trash2 size={13} className="text-status-fail" />
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
