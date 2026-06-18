import { useEffect, useState } from 'react'
import { api, User, UserRole } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, Select, useToast, Empty, timeAgo } from '@/components/ui'
import { Plus } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

const ROLE_CLASS: Record<UserRole, string> = {
  admin:     'text-status-review',
  operator:  'text-status-info',
  developer: 'text-status-pass',
  viewer:    'text-muted-foreground',
}

export default function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [showAdd, setShowAdd] = useState(false)
  const { show, Toast } = useToast()
  const { user: me } = useAuth()
  const isAdmin = me?.role === 'admin'

  const load = () => {
    setLoading(true)
    api.users.list().then(setUsers).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  return (
    <Shell>
      <PageHeader
        title="Users"
        subtitle="Manage access to PA Central"
        action={isAdmin ? <Button variant="primary" onClick={() => setShowAdd(true)}><Plus size={13} />Add user</Button> : undefined}
      />
      <div className="p-6 px-7 overflow-auto">
        {loading ? <div className="text-muted-foreground text-[13px]">Loading…</div> :
          users.length === 0 ? <Empty message="No users." /> : (
          <Card>
            <table className="w-full border-collapse">
              <thead>
                <tr className="border-b border-border">
                  {['Name', 'Email', 'Role', 'Status', 'Joined'].map(h => (
                    <th key={h} className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} className="border-b border-border/50">
                    <td className="px-4 py-2.5 font-medium text-[13px]">
                      {u.display_name}
                      {u.id === me?.id && <span className="text-[10px] text-muted-foreground ml-1.5">(you)</span>}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{u.email}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-style-caption ${ROLE_CLASS[u.role]}`}>{u.role}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[11px] ${u.is_active ? 'text-status-pass' : 'text-status-fail'}`}>
                        {u.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{timeAgo(u.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        )}
      </div>
      {showAdd && (
        <AddUserModal
          onClose={() => setShowAdd(false)}
          onSaved={() => { load(); setShowAdd(false); show('User created') }}
        />
      )}
      {Toast}
    </Shell>
  )
}

function AddUserModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<UserRole>('viewer')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const save = async () => {
    setSaving(true); setError('')
    try {
      await api.auth.register({ email, display_name: name, password, role })
      onSaved()
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="Add user" onClose={onClose}>
      <div className="flex flex-col gap-3.5">
        <Input label="Display name *" value={name} onChange={e => setName(e.target.value)} />
        <Input label="Email *" type="email" value={email} onChange={e => setEmail(e.target.value)} />
        <Input label="Password *" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Min 12 characters" minLength={12} />
        <Select label="Role" value={role} onChange={e => setRole(e.target.value as UserRole)}>
          <option value="viewer">Viewer — read-only access</option>
          <option value="developer">Developer — own hosts/scans/alerts + API keys</option>
          <option value="operator">Operator — can manage alerts, cooldowns, configs</option>
          <option value="admin">Admin — full access including user management</option>
        </Select>
        {error && <div className="text-status-fail-text text-xs">{error}</div>}
        <div className="flex gap-2 justify-end">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!email || !name || password.length < 12 || saving}>
            {saving ? 'Creating…' : 'Create user'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
