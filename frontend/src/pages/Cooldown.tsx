import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, CooldownEntry, Ecosystem, Host } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, Select, useToast, Empty, timeAgo, timeUntil } from '@/components/ui'
import { Plus, Trash2, Globe } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

export default function Cooldown() {
  const [entries, setEntries] = useState<CooldownEntry[]>([])
  const [hosts, setHosts] = useState<Host[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isOperator = user?.role === 'admin' || user?.role === 'operator'
  const hostMap = useMemo(() => new Map(hosts.map(h => [h.id, h])), [hosts])

  const load = useCallback(() => {
    setLoading(true)
    api.cooldown.list().then(setEntries).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }, [show])
  useEffect(() => {
    load() // eslint-disable-line react-hooks/set-state-in-effect
    api.hosts.list().then(setHosts).catch((e: any) => show(e.message, 'err'))
  }, [load, show])

  const del = async (id: number) => {
    try {
      await api.cooldown.delete(id)
      show('Entry removed')
      load()
    } catch (e: any) {
      show(e.message, 'err')
    }
  }

  return (
    <Shell>
      <PageHeader
        title="Cooldown allowlist"
        subtitle="Pre-cleared packages that bypass the recent-publish cooldown check"
        action={isOperator ? <Button variant="primary" onClick={() => setShowAdd(true)}><Plus size={13} />Add entry</Button> : undefined}
      />
      <div className="p-6 px-7 overflow-auto">
        {loading ? <div className="text-muted-foreground text-[13px]">Loading…</div> :
          entries.length === 0 ? <Empty message="No cooldown allowlist entries." /> : (
          <Card>
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-border">
                  {['Package', 'Version', 'Ecosystem', 'Scope', 'Note', 'Expires', 'Added'].map(h => (
                    <th key={h} scope="col" className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                  ))}
                  <th scope="col" className="px-4 py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {entries.map(e => {
                  const host = e.host_id != null ? hostMap.get(e.host_id) : undefined
                  return (
                    <tr key={e.id} className="border-b border-border/50">
                      <td className="px-4 py-2.5 font-mono text-xs font-medium">{e.package_name}</td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">{e.package_version || '*'}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{e.ecosystem}</td>
                      <td className="px-4 py-2.5">
                        {e.host_id == null ? (
                          <span className="inline-flex items-center gap-1 text-xs text-status-review">
                            <Globe size={12} />Fleet-wide
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">{host?.name || `#${e.host_id}`}</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{e.note || '—'}</td>
                      <td className="px-4 py-2.5 text-[11px] text-muted-foreground">
                        {e.expires_at ? timeUntil(e.expires_at) : '—'}
                      </td>
                      <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{timeAgo(e.created_at)}</td>
                      <td className="px-4 py-2.5">
                        {isOperator && (
                          <Button variant="ghost" onClick={() => del(e.id)} title={`Delete ${e.package_name}`} aria-label={`Delete ${e.package_name}`}>
                            <Trash2 size={13} className="text-status-fail" />
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </Card>
        )}
      </div>
      {showAdd && (
        <AddCooldownModal
          hosts={hosts}
          onClose={() => setShowAdd(false)}
          onSaved={() => { load(); setShowAdd(false); show('Entry added') }}
        />
      )}
      {Toast}
    </Shell>
  )
}

function AddCooldownModal({ hosts, onClose, onSaved }: { hosts: Host[]; onClose: () => void; onSaved: () => void }) {
  const [pkg, setPkg] = useState('')
  const [version, setVersion] = useState('')
  const [ecosystem, setEcosystem] = useState<Ecosystem>('pypi')
  const [hostId, setHostId] = useState<string>('')
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const save = async () => {
    setSaving(true); setError('')
    try {
      await api.cooldown.create({
        package_name: pkg,
        package_version: version || undefined,
        ecosystem,
        host_id: hostId ? Number(hostId) : null,
        note: note || undefined,
      })
      onSaved()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="Add cooldown allowlist entry" onClose={onClose}>
      <div className="flex flex-col gap-3.5">
        <Input label="Package name *" value={pkg} onChange={e => setPkg(e.target.value)} placeholder="requests" />
        <Input label="Version (blank = any)" value={version} onChange={e => setVersion(e.target.value)} placeholder="2.32.0" />
        <Select label="Ecosystem" value={ecosystem} onChange={e => setEcosystem(e.target.value as Ecosystem)}>
          <option value="pypi">PyPI</option>
          <option value="npm">npm</option>
          <option value="packagist">Packagist</option>
        </Select>
        <Select label="Scope" value={hostId} onChange={e => setHostId(e.target.value)}>
          <option value="">Fleet-wide</option>
          {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
        </Select>
        <Input label="Note" value={note} onChange={e => setNote(e.target.value)} placeholder="Approved in security review #42" />
        {error && <div className="text-status-fail-text text-xs">{error}</div>}
        <div className="flex gap-2 justify-end mt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!pkg || saving}>{saving ? 'Saving…' : 'Add entry'}</Button>
        </div>
      </div>
    </Modal>
  )
}
