import { useEffect, useState } from 'react'
import { api, ApiKey } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, useToast, Empty, timeAgo } from '@/components/ui'
import { Plus, Trash2, Copy, AlertCircle } from 'lucide-react'

export default function ApiKeys() {
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const [newKey, setNewKey] = useState<string | null>(null)
  const { show, Toast } = useToast()

  const load = () => {
    setLoading(true)
    api.apiKeys.list().then(setKeys).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  const revoke = async (id: number, name: string) => {
    if (!confirm(`Revoke key "${name}"?`)) return
    try {
      await api.apiKeys.revoke(id)
      show('Key revoked')
      load()
    } catch (e: any) {
      show(e.message, 'err')
    }
  }

  return (
    <Shell>
      <PageHeader
        title="API keys"
        subtitle="Keys used by agents to register and report into this fleet"
        action={<Button variant="primary" onClick={() => setShowAdd(true)}><Plus size={13} />New key</Button>}
      />
      <div className="p-6 px-7 overflow-auto">
        {newKey && (
          <div className="bg-status-pass/8 border border-status-pass/30 rounded-[var(--radius-lg)] px-5 py-4 mb-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle size={14} className="text-status-pass" />
              <span className="text-[13px] font-semibold text-status-pass">Copy this key now — it won't be shown again</span>
            </div>
            <div className="flex items-center gap-2">
              <code className="font-mono text-xs bg-muted px-3 py-1.5 rounded-[var(--radius-sm)] flex-1 break-all">
                {newKey}
              </code>
              <Button variant="secondary" onClick={async () => { try { await navigator.clipboard.writeText(newKey); show('Copied') } catch { show('Copy failed — select and copy manually', 'err') } }}>
                <Copy size={13} />Copy
              </Button>
              <Button variant="ghost" onClick={() => setNewKey(null)}>Dismiss</Button>
            </div>
          </div>
        )}

        {loading ? <div className="text-muted-foreground text-[13px]">Loading…</div> :
          keys.length === 0 ? <Empty message="No API keys. Create one and configure it in package-alert to register hosts." /> : (
          <Card>
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-border">
                  {['Name', 'Status', 'Last used', 'Created', ''].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {keys.map(k => (
                  <tr key={k.id} className={`border-b border-border/50 ${k.is_active ? '' : 'opacity-40'}`}>
                    <td className="px-4 py-2.5 font-medium text-[13px]">{k.name}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-style-caption ${k.is_active ? 'text-status-pass' : 'text-muted-foreground'}`}>
                        {k.is_active ? 'Active' : 'Revoked'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground">
                      {k.last_used_at ? timeAgo(k.last_used_at) : 'Never'}
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{timeAgo(k.created_at)}</td>
                    <td className="px-4 py-2.5">
                      {k.is_active && (
                        <Button variant="ghost" onClick={() => revoke(k.id, k.name)} title={`Revoke ${k.name}`} aria-label={`Revoke ${k.name}`}>
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
      {showAdd && (
        <AddKeyModal
          onClose={() => setShowAdd(false)}
          onSaved={(raw) => { load(); setShowAdd(false); setNewKey(raw) }}
        />
      )}
      {Toast}
    </Shell>
  )
}

function AddKeyModal({ onClose, onSaved }: { onClose: () => void; onSaved: (raw: string) => void }) {
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const save = async () => {
    setSaving(true); setError('')
    try {
      const k = await api.apiKeys.create({ name })
      if (!k.raw_key) throw new Error('Server did not return the API key')
      onSaved(k.raw_key)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="New API key" onClose={onClose}>
      <div className="flex flex-col gap-3.5">
        <Input label="Key name *" value={name} onChange={e => setName(e.target.value)} placeholder="prod-fleet-key" />
        <div className="text-xs text-muted-foreground">
          Configure this key in package-alert on each host. Hosts will register automatically on first heartbeat.
        </div>
        {error && <div className="text-status-fail-text text-xs">{error}</div>}
        <div className="flex gap-2 justify-end mt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!name || saving}>
            {saving ? 'Generating…' : 'Generate key'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
