import { Fragment, useCallback, useEffect, useState } from 'react'
import { api, User, UserRole } from '@/lib/api'
import { codePointLength, MAX_PASSWORD_BYTES, utf8ByteLength } from '@/lib/text'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, Select, useToast, Empty, timeAgo } from '@/components/ui'
import { Plus, Trash2, Copy, AlertCircle } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useLiveAlertsContext, PendingOp } from '@/hooks/useLiveAlerts'

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
  // Governs how a new user is handed their credential: an emailed welcome
  // link, or a password the admin types.
  //
  // Tri-state on purpose. Neither answer is a safe default while this is
  // unknown: with self-service on the backend *rejects* a supplied password,
  // and with it off a password is required — so guessing either way sends
  // the admin into a 400 they cannot act on. Add User stays unavailable
  // until the mode is known.
  const [selfServiceReset, setSelfServiceReset] = useState<boolean | null>(null)
  const [resetConfigError, setResetConfigError] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const { show, dismiss, Toast } = useToast()
  const { user: me } = useAuth()
  const { registerPendingOp, discardEarlyResult, getSessionEpoch } = useLiveAlertsContext()
  const isAdmin = me?.role === 'admin'

  const load = useCallback(() => {
    setLoading(true)
    api.users.list().then(setUsers).catch((e: any) => show(e.message, 'err')).finally(() => setLoading(false))
  }, [show])
  useEffect(() => { load() }, [load]) // eslint-disable-line react-hooks/set-state-in-effect

  // Refreshes the row data without ever touching `loading` — unlike load()
  // above, which the initial mount and AddUserModal's onSaved use, and
  // which flips the whole table to a "Loading…" placeholder while in
  // flight. That placeholder unmounts UserEditPanel entirely, destroying
  // its local newPassword state — a generated password waiting to be
  // copied would be silently lost the moment a reset's own row-refresh
  // fired, reproduced directly with any real network latency (a mocked,
  // same-tick-resolving fetch in a test can hide this, since React 19
  // batches the loading flip away when nothing ever renders in between —
  // but a real fetch always has a window where it doesn't). Used by
  // doResetPassword, which sets newPassword in the very same call.
  const reloadSilently = useCallback(() => {
    api.users.list().then(setUsers).catch((e: any) => show(e.message, 'err'))
  }, [show])

  // Clearing the error is left to the retry handler rather than done here:
  // on mount there is nothing to clear, and doing it in the effect body is a
  // synchronous setState that triggers a cascading render.
  const loadResetConfig = useCallback(() => {
    api.auth.passwordResetConfig()
      .then(cfg => {
        setSelfServiceReset(cfg.self_service_enabled)
        setResetConfigError(false)
      })
      .catch(() => setResetConfigError(true))
  }, [])
  useEffect(() => { loadResetConfig() }, [loadResetConfig])

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
        action={isAdmin ? (
          <Button
            variant="primary"
            onClick={() => setShowAdd(true)}
            // Unavailable until the credential mode is known: the form's
            // shape depends on it, and either guess produces a request the
            // backend rejects.
            disabled={selfServiceReset === null}
            title={selfServiceReset === null
              ? (resetConfigError
                  ? 'Cannot add users — the password reset mode could not be loaded'
                  : 'Loading…')
              : undefined}
          >
            <Plus size={13} />Add user
          </Button>
        ) : undefined}
      />
      <div className="p-6 px-7 overflow-auto">
        {resetConfigError && isAdmin && (
          <div className="mb-4 flex items-center gap-3 text-[13px] text-status-fail-text bg-status-fail/10 border border-status-fail/30 rounded-[var(--radius-sm)] px-4 py-3">
            <span className="flex-1">
              Could not load the password reset mode, so new users cannot be
              added yet — the form depends on whether they set their own
              password or you do.
            </span>
            <Button onClick={loadResetConfig}>Retry</Button>
          </div>
        )}
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
                              dismiss={dismiss}
                              registerPendingOp={registerPendingOp}
                              discardEarlyResult={discardEarlyResult}
                              getSessionEpoch={getSessionEpoch}
                              reload={reloadSilently}
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
      {showAdd && selfServiceReset !== null && (
        <AddUserModal
          selfServiceReset={selfServiceReset}
          onClose={() => setShowAdd(false)}
          registerPendingOp={registerPendingOp}
          discardEarlyResult={discardEarlyResult}
          getSessionEpoch={getSessionEpoch}
          dismiss={dismiss}
          onSaved={(status) => {
            load()
            setShowAdd(false)
            if (status === 'resolved') {
              // The outcome already arrived and registerPendingOp already
              // rendered the real, final toast via the SSE event — showing
              // "sending…" now would follow it with a stale message.
            } else if (status === 'pending') {
              show('Account created — sending welcome link…')
            } else if (status === 'prep_failed') {
              show("Account created, but the welcome email could not be prepared — resend from the user's row once the issue is fixed.", 'err')
            } else if (status === 'admission_refused') {
              show("Account created, but too many pending admin actions — resend the welcome email from the user's row shortly.", 'err')
            } else {
              show('User created')
            }
          }}
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
  dismiss,
  registerPendingOp,
  discardEarlyResult,
  getSessionEpoch,
  reload,
}: {
  user: User
  onSaved: (updated: User) => void
  onDiscard: () => void
  show: (msg: string, type?: 'err') => void
  dismiss: () => void
  registerPendingOp: (opId: string, entry: PendingOp) => boolean
  discardEarlyResult: (opId: string) => void
  getSessionEpoch: () => number
  // Refreshes this row's data (e.g. has_outstanding_welcome_token) without
  // unmounting this panel — see reloadSilently's own docstring for why
  // that distinction matters here specifically.
  reload: () => void
}) {
  const [draftRole, setDraftRole] = useState<UserRole>(user.role)
  const [draftActive, setDraftActive] = useState(user.is_active)
  const [saving, setSaving] = useState(false)
  const [confirmReset, setConfirmReset] = useState(false)
  const [confirmPasswordReset, setConfirmPasswordReset] = useState(false)
  const [newPassword, setNewPassword] = useState<string | null>(null)

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
    setConfirmPasswordReset(false)
    setNewPassword(null)
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

  const doResetPassword = async () => {
    setSaving(true)
    // Drop any password from a previous reset before starting this one. It is
    // already dead — every reset invalidates the current credential — so
    // leaving it on screen invites the admin to copy and relay something that
    // no longer works. Cleared here rather than per-outcome so it also covers
    // the emailed-link result and a failure, neither of which sets it.
    setNewPassword(null)
    // Captured before the await, not after: a logout mid-request bumps the
    // session epoch, and registering a pending op under the *new* epoch
    // would let a stale response from the old session resolve against the
    // wrong (or a future, coincidentally-reused) session.
    const opEpoch = getSessionEpoch()
    try {
      // Either way the current password stops working immediately. The
      // outcomes differ in how the user gets a new one: a link emailed to
      // them (possibly via a background send this response doesn't wait
      // on), or a generated password shown once for the admin to relay.
      const { password, reset_link_sent, op_id } = await api.users.resetPassword(user.id)
      setConfirmPasswordReset(false)
      // has_outstanding_welcome_token is settled server-side by the time
      // this response returns, in every branch below: set_password (which
      // retires the old welcome token, if any) and prepare_reset_email
      // (which commits any new one) both already ran and committed before
      // reset_password ever builds its response — the only thing still
      // pending for the op_id branch is whether the *send* itself
      // succeeds, which doesn't change whether the token row exists. A
      // stale `user` prop otherwise keeps showing "Resend welcome email"
      // (or "Reset password") after the real state has already flipped —
      // reload() re-fetches the list so this row's button label reflects
      // the outcome that already happened, not the pre-reset snapshot.
      // The silent variant specifically: this function sets newPassword
      // itself, below, and that state lives in this very panel — a
      // refresh that unmounts the panel to show "Loading…" would destroy
      // it before the admin ever sees it.
      reload()
      // reset_link_sent === false is checked BEFORE op_id: it covers all
      // three settled-outcome backend branches that return no genuinely
      // pending send — a generated-password fallback (password set),
      // preparation failing outright (password null, op_id null), AND
      // admission being refused (password null, op_id SET —
      // reset_password's own comment is explicit: "no further SSE outcome
      // will arrive beyond the attempted=False event it already emitted",
      // this response IS the settled answer). Checking op_id ahead of
      // reset_link_sent would treat that already-decided failure as
      // still-pending whenever the SSE event it refers to was missed
      // (dropped during a reconnect, or simply not yet delivered when
      // this response is processed — the two race independently), leaving
      // a "sending reset link…" toast that can never resolve, since no
      // second event is ever coming. reset_link_sent is never true on the
      // wire (every backend branch returns False or None; verified
      // exhaustively against every PasswordResetOut construction site) —
      // an emailed-link result is only ever reported later, via the
      // op_id/SSE path below, never synchronously as True.
      if (reset_link_sent === false) {
        if (password) {
          setNewPassword(password)
        } else if (op_id) {
          // Preparation succeeded (a token/message were built) but
          // dispatch admission was refused — the admin-send queue was
          // full. Distinct from true preparation failure below: nothing
          // is misconfigured here, so pointing the admin at SMTP/account
          // settings would send them chasing a problem that isn't there.
          // Settled, not pending — reset_password's own comment is
          // explicit that no further SSE outcome follows this response.
          //
          // dispatch_admin_action still emits its own SSE event for this
          // op_id (the same "attempted=False" notification whichever
          // caller triggered it); this response already reports the exact
          // same outcome synchronously, so there's nothing left for that
          // event to tell us. Drop it if it happens to already be sitting
          // in earlyResults (arrived before this response did) rather than
          // leaving it there — it can only ever be discarded, never
          // consumed, since no registerPendingOp call for this op_id is
          // ever going to come.
          discardEarlyResult(op_id)
          show(
            'Password invalidated, but too many pending admin actions — try resetting again shortly',
            'err',
          )
        } else {
          show(
            'Password invalidated, but no reset email could be prepared — try again, or check the account/SMTP configuration',
            'err',
          )
        }
      } else if (op_id) {
        // Reaches here only when reset_link_sent is still null — the one
        // case genuinely still in flight — so reconcile via the
        // admin-alerts SSE stream.
        const stillPending = registerPendingOp(op_id, { action: 'admin_reset', dismiss, epoch: opEpoch })
        if (stillPending) {
          show('Password invalidated — sending reset link…')
        }
        // else: the outcome had already arrived and registerPendingOp just
        // rendered the real, final toast — showing "sending…" now would
        // follow it with a stale message for an operation that's already done.
      }
    } catch (e: any) {
      show(e.message, 'err')
    } finally {
      setSaving(false)
    }
  }

  const dirty = draftRole !== user.role || draftActive !== user.is_active

  return (
    <div className="flex flex-col gap-3">
      {newPassword && (
        <div className="bg-status-pass/8 border border-status-pass/30 rounded-[var(--radius-lg)] px-5 py-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle size={14} className="text-status-pass" />
            <span className="text-[13px] font-semibold text-status-pass">Copy this password now — it won't be shown again</span>
          </div>
          <div className="flex items-center gap-2">
            <code className="font-mono text-xs bg-muted px-3 py-1.5 rounded-[var(--radius-sm)] flex-1 break-all">
              {newPassword}
            </code>
            <Button variant="secondary" onClick={async () => { try { await navigator.clipboard.writeText(newPassword); show('Copied') } catch { show('Copy failed — select and copy manually', 'err') } }}>
              <Copy size={13} />Copy
            </Button>
            <Button variant="ghost" onClick={() => setNewPassword(null)}>Dismiss</Button>
          </div>
        </div>
      )}
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
          {!confirmPasswordReset && (
            <Button onClick={() => setConfirmPasswordReset(true)} disabled={saving}>
              {user.has_outstanding_welcome_token ? 'Resend welcome email' : 'Reset password'}
            </Button>
          )}
          {confirmPasswordReset && (
            <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
              {/* The admin needs to know this locks the user out now, not
                  once they get round to clicking a link — it is the point of
                  the action, but it is destructive and worth stating. */}
              <span>Invalidate this password now? {user.display_name} will need the reset to sign in again.</span>
              <Button variant="danger" onClick={doResetPassword} disabled={saving}>
                {user.has_outstanding_welcome_token ? 'Resend welcome email' : 'Reset password'}
              </Button>
              <Button onClick={() => setConfirmPasswordReset(false)} disabled={saving}>Cancel</Button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function AddUserModal({
  onClose, onSaved, selfServiceReset, registerPendingOp, discardEarlyResult, getSessionEpoch, dismiss,
}: {
  onClose: () => void
  // The exhaustive set of outcomes save() can produce: 'pending'/'resolved'
  // for a dispatch attempt (still in flight, or already reconciled from an
  // early SSE event); 'prep_failed' when nothing was ever dispatched (no
  // op_id — a true preparation failure, e.g. SMTP unconfigured);
  // 'admission_refused' when preparation succeeded but the admin-send
  // queue was full (op_id set, but settled — no SSE event is still
  // pending; see save()'s own comment); 'password-set' when self-service
  // is off.
  onSaved: (status: 'pending' | 'resolved' | 'prep_failed' | 'admission_refused' | 'password-set') => void
  selfServiceReset: boolean
  registerPendingOp: (opId: string, entry: PendingOp) => boolean
  discardEarlyResult: (opId: string) => void
  getSessionEpoch: () => number
  dismiss: () => void
}) {
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<UserRole>('viewer')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  // Mirrors UserCreate's own bcrypt-byte-limit validator (schemas/__init__.py's
  // _reject_password_over_bcrypt_limit): bcrypt hashes only the first 72
  // *bytes*, and a password that looks short by character count can still
  // exceed that — 40 "é" characters is 40 code points (well past the min-12
  // check below) but 80 UTF-8 bytes, so it passed this form and was rejected
  // by the backend with no explanation shown here. Checked only when
  // self-service is off — this field doesn't exist otherwise.
  const passwordTooLong = !selfServiceReset && utf8ByteLength(password) > MAX_PASSWORD_BYTES

  const save = async () => {
    setSaving(true); setError('')
    // Captured before the await, not after: a logout mid-request bumps the
    // session epoch, and registering a pending op under the *new* epoch
    // would let a stale response resolve against the wrong session.
    const opEpoch = getSessionEpoch()
    try {
      // With self-service on the user sets their own password via an emailed
      // welcome link, and the backend rejects a supplied one outright — so
      // the field is omitted rather than sent empty.
      const result = await api.auth.register({
        email, display_name: name, role,
        ...(selfServiceReset ? {} : { password }),
      })
      // welcome_email_sent === false is checked BEFORE op_id: it covers
      // two distinct backend branches that both still carry an op_id —
      // preparation failing outright (op_id null) AND admission being
      // refused (op_id set, but register()'s own comment is explicit:
      // "no further SSE outcome will arrive beyond the attempted=False
      // event it already emitted" — this response IS the settled answer).
      // Checking op_id first would treat that already-decided failure as
      // still-pending whenever the SSE event it refers to was missed
      // (dropped during a reconnect, or simply not yet delivered when
      // this response is processed — the two race independently), leaving
      // a "sending welcome link…" toast that can never resolve, since no
      // second event is ever coming. welcome_link_still_valid is NOT
      // checked here at all: on the admission-refused branch it is true
      // (a live token was already committed before dispatch was ever
      // attempted, and refused admission never retires it) even though
      // welcome_email_sent is false — see api.ts's own comment on
      // RegisterResult — so checking it here couldn't distinguish
      // anything welcome_email_sent doesn't already, and would be
      // actively misleading read on its own.
      if (result?.welcome_email_sent === false) {
        // op_id distinguishes two settled-failure causes that both report
        // welcome_email_sent === false: null means preparation itself
        // never produced anything to dispatch (SMTP unconfigured, rate-
        // limited, or lock-contention abandonment — see register()'s own
        // comment); set means preparation succeeded and dispatch admission
        // was refused (the admin-send queue was full) — a transient
        // capacity issue with nothing wrong to configure. Conflating them
        // sent an admin toward checking SMTP/account config for a problem
        // that was actually "try again in a minute."
        if (result.op_id) {
          // register() still emits its own SSE event for this op_id (the
          // same "attempted=False" notification reset_password's
          // admission-refused branch produces); this response already
          // reports the identical outcome synchronously, so there's
          // nothing left for that event to tell us — drop it if it's
          // already sitting in earlyResults rather than leaving it there,
          // since no registerPendingOp call for this op_id is ever coming.
          discardEarlyResult(result.op_id)
        }
        onSaved(result.op_id ? 'admission_refused' : 'prep_failed')
      } else if (result?.op_id) {
        // Reaches here only when welcome_email_sent is still null — the
        // one case genuinely still in flight — so reconcile via the
        // admin-alerts SSE stream.
        const stillPending = registerPendingOp(result.op_id, { action: 'welcome_link', dismiss, epoch: opEpoch })
        // 'resolved': the outcome had already arrived and registerPendingOp
        // just rendered the real, final toast — the caller must not follow
        // it with its own "sending…" toast for an operation that's already done.
        onSaved(stillPending ? 'pending' : 'resolved')
        return
      } else {
        // self-service reset is off entirely: no welcome link was ever
        // created, and the admin-supplied password is already live.
        onSaved('password-set')
      }
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
        {selfServiceReset ? (
          <p className="text-xs text-muted-foreground leading-relaxed">
            They'll be emailed a link to set their own password. The link is
            valid for 7 days.
          </p>
        ) : (
          <div className="flex flex-col gap-1">
            <Input label="Password *" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Min 12 characters" minLength={12} />
            {passwordTooLong && (
              <span className="text-status-fail-text text-xs">
                Too long: passwords can be at most {MAX_PASSWORD_BYTES} bytes
                once encoded — non-ASCII characters (accents, emoji) can use
                more than one byte each.
              </span>
            )}
          </div>
        )}
        <Select label="Role" value={role} onChange={e => setRole(e.target.value as UserRole)}>
          <option value="viewer">Viewer — read-only access</option>
          <option value="developer">Developer — own hosts/scans/alerts + API keys</option>
          <option value="operator">Operator — can manage alerts, cooldowns, configs</option>
          <option value="admin">Admin — full access including user management</option>
        </Select>
        {error && <div className="text-status-fail-text text-xs">{error}</div>}
        <div className="flex gap-2 justify-end">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save}
            disabled={!email || !name || (!selfServiceReset && codePointLength(password) < 12) || passwordTooLong || saving}>
            {saving ? 'Creating…' : selfServiceReset ? 'Create & send invite' : 'Create user'}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
