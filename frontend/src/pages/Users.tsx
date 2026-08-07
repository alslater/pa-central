import { Fragment, useCallback, useEffect, useState } from 'react'
import { api, User, UserRole } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, Select, useToast, Empty, timeAgo } from '@/components/ui'
import { Plus, Trash2 } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

const COLUMNS = ['Name', 'Email', 'Role', 'Status', 'Joined'] as const
// Data columns plus the trailing actions column. The expanded edit row spans
// the full table, so it must stay in sync with the header.
const COLUMN_COUNT = COLUMNS.length + 1

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
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const { show, Toast } = useToast()
  const { user: me } = useAuth()
  const isAdmin = me?.role === 'admin'

  const load = useCallback(() => {
    setLoading(true)
    api.users.list().then(setUsers).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }, [show])
  useEffect(() => { load() }, [load]) // eslint-disable-line react-hooks/set-state-in-effect

  const handleSaved = (updated: User) => {
    setUsers(prev => prev.map(u => u.id === updated.id ? updated : u))
    setExpandedId(null)
  }

  const deleteUser = async (u: User) => {
    if (!confirm(`Delete ${u.display_name}? This cannot be undone.`)) return
    try {
      await api.users.delete(u.id)
      setUsers(prev => prev.filter(x => x.id !== u.id))
      // Only collapse if the deleted row is the expanded one — collapsing
      // unconditionally would discard another row's unsaved edits.
      setExpandedId(prev => prev === u.id ? null : prev)
      show('User deleted')
    } catch (e: any) {
      show(e.message, 'err')
    }
  }

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
                  {COLUMNS.map(h => (
                    <th key={h} scope="col" className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                  ))}
                  <th scope="col" className="px-4 py-2.5"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => {
                  const isMe = u.id === me?.id
                  const expanded = expandedId === u.id
                  const canExpand = isAdmin && !isMe
                  return (
                    <Fragment key={u.id}>
                      <tr
                        className={`border-b border-border/50 ${canExpand ? 'cursor-pointer hover:bg-muted/30' : ''} ${expanded ? 'bg-muted/30' : ''}`}
                        onClick={() => canExpand && setExpandedId(expanded ? null : u.id)}
                      >
                        <td className="px-4 py-2.5 font-medium text-[13px]">
                          {u.display_name}
                          {isMe && <span className="text-[10px] text-muted-foreground ml-1.5">(you)</span>}
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
                        <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}>
                          {canExpand && (
                            <Button variant="ghost" onClick={() => void deleteUser(u)} title={`Delete ${u.display_name}`} aria-label={`Delete ${u.display_name}`}>
                              <Trash2 size={13} className="text-status-fail" />
                            </Button>
                          )}
                        </td>
                      </tr>
                      {expanded && (
                        <tr key={`${u.id}-expanded`} className="border-b border-border/50 bg-muted/20">
                          <td colSpan={COLUMN_COUNT} className="px-4 py-3">
                            <UserEditPanel
                              user={u}
                              onSaved={handleSaved}
                              onDiscard={() => setExpandedId(null)}
                              show={show}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
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

function UserEditPanel({
  user,
  onSaved,
  onDiscard,
  show,
}: {
  user: User
  onSaved: (updated: User) => void
  onDiscard: () => void
  show: (msg: string, type?: 'err') => void
}) {
  const [draftRole, setDraftRole] = useState<UserRole>(user.role)
  const [draftActive, setDraftActive] = useState(user.is_active)
  const [saving, setSaving] = useState(false)
  const [confirmReset, setConfirmReset] = useState(false)

  // Re-sync drafts when the target user's server state changes underneath an
  // open panel. React 19 batches load()'s setLoading(true) with the updates
  // from the resolved fetch, so the "Loading…" branch never commits and this
  // panel is no longer unmounted by a refresh — it keeps whatever drafts it
  // had. Without this, `dirty` compares stale drafts against the new prop, so
  // an untouched panel looks dirty and Save would push a value nobody chose.
  // (On React 18 the loading swap did commit, which is why this wasn't needed.)
  // Adjusted during render rather than in an effect: React's documented
  // pattern, and it avoids rendering one frame of stale values.
  const identity = `${user.id}:${user.role}:${user.is_active}:${user.totp_enabled}`
  const [syncedIdentity, setSyncedIdentity] = useState(identity)
  if (syncedIdentity !== identity) {
    setSyncedIdentity(identity)
    setDraftRole(user.role)
    setDraftActive(user.is_active)
    setConfirmReset(false)
  }

  const save = async () => {
    setSaving(true)
    try {
      const updated = await api.users.update(user.id, { role: draftRole, is_active: draftActive })
      onSaved(updated)
      show('User updated')
    } catch (e: any) {
      show(e.message, 'err')
    } finally {
      setSaving(false)
    }
  }

  const doResetTotp = async () => {
    setSaving(true)
    try {
      const updated = await api.users.resetTotp(user.id)
      onSaved(updated)
      show('TOTP reset — user must re-enrol on next login')
    } catch (e: any) {
      show(e.message, 'err')
    } finally {
      setSaving(false)
    }
  }

  const dirty = draftRole !== user.role || draftActive !== user.is_active

  return (
    <div className="flex flex-wrap items-end gap-3">
      <Select
        label="Role"
        value={draftRole}
        onChange={e => setDraftRole(e.target.value as UserRole)}
      >
        <option value="viewer">Viewer</option>
        <option value="developer">Developer</option>
        <option value="operator">Operator</option>
        <option value="admin">Admin</option>
      </Select>
      <Select
        label="Status"
        value={draftActive ? 'active' : 'disabled'}
        onChange={e => setDraftActive(e.target.value === 'active')}
      >
        <option value="active">Active</option>
        <option value="disabled">Disabled</option>
      </Select>
      <div className="flex gap-2 items-center">
        <Button variant="primary" onClick={save} disabled={!dirty || saving}>
          {saving ? 'Saving…' : 'Save'}
        </Button>
        <Button onClick={onDiscard} disabled={saving}>Discard</Button>
      </div>
      <div className="flex gap-2 items-center ml-auto">
        {user.totp_enabled && !confirmReset && (
          <Button onClick={() => setConfirmReset(true)} disabled={saving}>Reset TOTP</Button>
        )}
        {confirmReset && (
          <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
            <span>Reset TOTP?</span>
            <Button variant="primary" onClick={doResetTotp} disabled={saving}>Confirm</Button>
            <Button onClick={() => setConfirmReset(false)} disabled={saving}>Cancel</Button>
          </div>
        )}
      </div>
    </div>
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
