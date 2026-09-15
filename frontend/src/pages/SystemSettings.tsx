import { useCallback, useEffect, useRef, useState } from 'react'
import { api, type PasswordResetReadiness, type SystemSetting } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Select, useToast } from '@/components/ui'
import { useAuth } from '@/hooks/useAuth'
import { TimezoneField } from '@/components/TimezoneField'

const KNOWN_SETTINGS: Array<{
  key: string; label: string; hint?: string
  type: 'string' | 'int' | 'bool' | 'secret'
}> = [
  { key: 'smtp_host',      label: 'SMTP Host',     hint: 'e.g. smtp.example.com', type: 'string' },
  { key: 'smtp_port',      label: 'SMTP Port',     hint: '587', type: 'int' },
  { key: 'smtp_username',  label: 'SMTP Username', type: 'string' },
  { key: 'smtp_password',  label: 'SMTP Password', type: 'secret' },
  { key: 'smtp_from',      label: 'From Address',  hint: 'pa-central@example.com', type: 'string' },
  { key: 'smtp_tls_mode',  label: 'TLS Mode',      type: 'string' },
  { key: 'smtp_timeout_seconds', label: 'Timeout (seconds)', hint: '30 — how long to wait on an unresponsive server', type: 'string' },
  { key: 'scan_result_retention_days',  label: 'Retention (days)',  hint: 'e.g. 30', type: 'int' },
  { key: 'scan_result_retention_count', label: 'Retention (count)', hint: 'e.g. 100', type: 'int' },
  { key: 'sla_high_days',           label: 'SLA: High/Critical (days)', hint: 'e.g. 14', type: 'int' },
  { key: 'sla_medium_days',         label: 'SLA: Medium (days)',        hint: 'e.g. 90', type: 'int' },
  { key: 'finding_retention_days',  label: 'Finding & risk retention (days)',  hint: 'e.g. 365 — also applies to closed risks', type: 'int' },
  { key: 'app_base_url',         label: 'App Base URL',          hint: 'https://pa-central.example.com', type: 'string' },
  { key: 'default_cron_timezone', label: 'Default cron timezone', hint: 'IANA name, e.g. Europe/London — leave blank for UTC', type: 'string' },
  { key: 'self_service_password_reset', label: 'Self-service password reset', type: 'bool' },
]

const SECRET_KEYS = new Set(KNOWN_SETTINGS.filter(s => s.type === 'secret').map(s => s.key))

// Values the backend treats as true (system_settings.py TRUE_VALUES). It
// canonicalises bools to "true"/"false" on write, so anything else is a row
// stored before that — or written directly to the database. Parsing the same
// set here means such a row still reads correctly instead of displaying as
// off and being overwritten with "false" by an unrelated save.
const TRUE_VALUES = new Set(['true', '1', 'yes', 'on'])

function isTrue(value: string | undefined): boolean {
  return TRUE_VALUES.has((value ?? '').trim().toLowerCase())
}

// Fields the backend's readiness check depends on. Readiness itself only
// ever reflects the last *persisted* state (see readiness's own comment
// below), so an unsaved edit to any of these must disable the toggle
// rather than let it show a verdict about values that were never sent.
const RESET_DEPENDENCY_KEYS = [
  'smtp_host', 'smtp_port', 'smtp_tls_mode', 'smtp_from', 'app_base_url',
]

export default function SystemSettings() {
  const [settings, setSettings] = useState<Record<string, string>>({})
  // The last state actually confirmed by the backend (initial load, or the
  // response to a successful save) — distinct from `settings`, which also
  // holds in-progress, unsaved edits. Diffing the two is how the reset
  // toggle knows a dependency field has been touched since the readiness
  // verdict below was computed.
  const [savedSettings, setSavedSettings] = useState<Record<string, string>>({})
  // Keys the backend reported as is_default: true — the field shows the
  // runtime value the app is actually using (e.g. sla_high_days=14), but
  // nobody has saved it, so it isn't a persisted admin choice.
  const [defaultKeys, setDefaultKeys] = useState<Set<string>>(new Set())
  // Tracks which secret fields the user has actually typed into this session.
  // Secret fields not in this set are excluded from the PATCH so we never
  // overwrite a stored secret with an empty string.
  const [dirtySecrets, setDirtySecrets] = useState<Set<string>>(new Set())
  const [saving, setSaving] = useState(false)
  // True once the initial GET has landed at least once. Before that,
  // `settings`/`savedSettings` are both {} — not because the account has no
  // dependency fields set, but because nothing has loaded yet — and
  // hasUnsavedDependencyEdits below cannot tell those two apart from an
  // empty object alone. Gating the toggle/save controls on this closes the
  // gap where readiness resolves before the mount-time list() call does:
  // `canEnableReset` would otherwise read as true from an empty draft
  // agreeing with an empty "last saved" snapshot, purely because neither
  // has loaded, and an admin could save on the strength of a verdict that
  // was never actually computed against this account's real settings.
  const [settingsLoaded, setSettingsLoaded] = useState(false)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  // Backend-derived readiness (SMTP host/port/TLS mode/From address, App
  // Base URL shape and scheme) via the same validators patch_settings()
  // and self_service_reset_enabled() use. A frontend re-derivation from
  // just smtp_host/app_base_url being non-empty previously disagreed with
  // the backend for every other precondition: the toggle looked enableable
  // while enabling it would 400, or looked active while the backend
  // already considered it unavailable.
  //
  // This only ever reflects the last *persisted* state — it is fetched on
  // load and after a successful save, never on every keystroke — so an
  // edit made since then (filling in a previously-missing field, or
  // clearing a previously-valid one) is invisible to it until the next
  // save. hasUnsavedDependencyEdits below closes that gap: rather than
  // live-validating the draft against the backend on every keystroke, the
  // toggle simply refuses to act on a stale verdict once any field it
  // depends on has diverged from what that verdict was actually computed
  // against.
  const [readiness, setReadiness] = useState<PasswordResetReadiness | null>(null)
  const hasUnsavedDependencyEdits = RESET_DEPENDENCY_KEYS.some(
    key => (settings[key] ?? '') !== (savedSettings[key] ?? '')
  )
  const canEnableReset = settingsLoaded && (readiness?.ready ?? false) && !hasUnsavedDependencyEdits
  const selfServiceOn = isTrue(settings['self_service_password_reset'])

  const applyRows = (rows: SystemSetting[]) => {
    const m: Record<string, string> = {}
    const defaults = new Set<string>()
    for (const r of rows) {
      m[r.key] = r.value ?? ''
      if (r.is_default) defaults.add(r.key)
    }
    setSettings(m)
    setSavedSettings(m)
    setDefaultKeys(defaults)
    setSettingsLoaded(true)
  }

  // loadReadiness runs twice per save cycle — once on mount, once right
  // after a successful save — and the two requests race: nothing guarantees
  // the mount-time fetch resolves before the post-save one. If the older
  // request lands second, applying its response unconditionally would
  // overwrite the fresh post-save verdict with a stale one — reproduced
  // directly: holding the mount fetch open until after a save completed
  // (with a post-save response of ready:false) and then resolving it with
  // the earlier ready:true left the toggle looking enableable again,
  // indefinitely, since nothing re-fetches after this. requestSeq tags each
  // call with an incrementing id at the moment it's issued and only applies
  // a response if it's still the most recently *issued* call by the time it
  // resolves — not the most recently *resolved* one, which is exactly what
  // was going wrong.
  const readinessRequestSeq = useRef(0)
  const loadReadiness = useCallback(() => {
    const seq = ++readinessRequestSeq.current
    api.systemSettings.passwordResetReadiness()
      .then(r => { if (seq === readinessRequestSeq.current) setReadiness(r) })
      .catch(e => { if (seq === readinessRequestSeq.current) show(e.message, 'err') })
  }, [show])

  // list() has the identical race: it runs once on mount and again right
  // after a successful save, and nothing guarantees the mount-time fetch
  // resolves first. Applying an out-of-order response unconditionally would
  // let a slow initial load clobber the freshly-saved state once it finally
  // resolves — reproduced directly: holding the mount-time list() open,
  // saving a genuine change in the meantime (whose own list() call resolves
  // first and applies the new state), then resolving the stale mount
  // response left the page showing the pre-save values indefinitely, even
  // though the backend already had the change. settingsRequestSeq applies
  // the same "most recently issued, not most recently resolved" guard
  // loadReadiness already uses.
  const settingsRequestSeq = useRef(0)
  const loadSettings = useCallback(() => {
    const seq = ++settingsRequestSeq.current
    api.systemSettings.list()
      .then(rows => { if (seq === settingsRequestSeq.current) applyRows(rows) })
      .catch(e => { if (seq === settingsRequestSeq.current) show(e.message, 'err') })
  }, [show])

  const load = useCallback(() => {
    loadSettings()
    loadReadiness()
  }, [loadSettings, loadReadiness])
  useEffect(() => { load() }, [load])

  const set = (key: string, val: string) => {
    setSettings(prev => ({ ...prev, [key]: val }))
    if (SECRET_KEYS.has(key)) setDirtySecrets(prev => new Set(prev).add(key))
    // Editing a field is a deliberate choice, even if the typed value
    // happens to match the default — it stops being an unsaved fallback.
    setDefaultKeys(prev => { if (!prev.has(key)) return prev; const n = new Set(prev); n.delete(key); return n })
  }

  const save = async () => {
    setSaving(true)
    const updates: Record<string, string | null> = {}
    for (const { key } of KNOWN_SETTINGS) {
      if (SECRET_KEYS.has(key) && !dirtySecrets.has(key)) continue
      // Only patch keys the user has actually loaded or edited; skip keys that
      // were never populated so we don't overwrite DB values with null.
      if (!(key in settings)) continue
      // Still showing a synthesized runtime default the admin hasn't
      // touched — must not be persisted as a side effect of an unrelated
      // save, or "using default" silently becomes "explicitly saved".
      if (defaultKeys.has(key)) continue
      updates[key] = settings[key] === '' ? null : settings[key]
    }
    // A bool is never "unset" from the UI's point of view — an unchecked box
    // is a saved false, not a cleared row, so it bypasses the empty-to-null
    // rule above that the text fields rely on.
    for (const { key, type } of KNOWN_SETTINGS) {
      if (type === 'bool' && key in settings) {
        updates[key] = isTrue(settings[key]) ? 'true' : 'false'
      }
    }
    // Mirrors patch_settings' own turning_off/losing_smtp: this save
    // retires *every* outstanding reset token system-wide — admin-reset
    // and welcome links included, for every user, not just whatever this
    // admin meant to change — when it genuinely flips self-service reset
    // from on to off, or genuinely clears an smtp_host that was actually
    // set. Both compare against savedSettings (the last-confirmed-
    // persisted state), not just what's being submitted: a save that only
    // resubmits the current off/empty value (which this page's own bool
    // handling above does on every save, whether or not the admin touched
    // it) must not warn about a transition that isn't happening.
    const wasResetOn = isTrue(savedSettings['self_service_password_reset'])
    const turningOff = 'self_service_password_reset' in updates
      && !isTrue(updates['self_service_password_reset'] ?? '')
      && wasResetOn
    const hadSmtpHost = (savedSettings['smtp_host'] ?? '').trim() !== ''
    const losingSmtp = 'smtp_host' in updates
      && !(updates['smtp_host'] ?? '').trim()
      && hadSmtpHost
    // Mirrors the backend's own changing_base_url condition
    // (api/system_settings.py): a link already emailed is built against
    // the *old* app_base_url and stays redeemable at whatever host serves
    // this API regardless — consume_reset_token isn't bound to which
    // origin issued the link. Changing the URL therefore retires every
    // outstanding token exactly like turning the feature off or losing
    // SMTP does, so it needs the same up-front warning.
    const priorBaseUrl = (savedSettings['app_base_url'] ?? '').trim()
    const changingBaseUrl = 'app_base_url' in updates
      && (updates['app_base_url'] ?? '').trim() !== priorBaseUrl
      && priorBaseUrl !== ''
    if (turningOff || losingSmtp || changingBaseUrl) {
      const proceed = confirm(
        'This will invalidate every outstanding password reset link — ' +
        'including admin-initiated resets and welcome links for other ' +
        'users — not just the "Forgot password?" flow. Anyone who has ' +
        "not yet used their link will need a new one issued. Continue?"
      )
      if (!proceed) {
        setSaving(false)
        return
      }
    }
    try {
      const rows = await api.systemSettings.update(updates)
      // Invalidate any list() call already in flight (the mount-time load,
      // if it is unusually slow, or another in-progress refresh) before
      // applying this response — otherwise that older call landing after
      // this one would overwrite the state this save just confirmed with
      // whatever it saw before the save happened. See loadSettings' own
      // comment for the reproduction.
      settingsRequestSeq.current++
      applyRows(rows)
      // applyRows just made `settings` and `savedSettings` identical again,
      // so hasUnsavedDependencyEdits drops to false immediately — but the
      // still-in-flight readiness fetch below reflects the *previous*
      // persisted state, not what was just saved. Without clearing it
      // first, canEnableReset would combine "no unsaved edits" (now true)
      // with "stale readiness" (from before this save) for the whole
      // window until the fetch resolves — and indefinitely if it fails,
      // since the catch below never calls setReadiness. Reproduced
      // directly: saving a cleared smtp_host with the flag off left the
      // toggle enabled again the instant the save completed, until (or
      // unless) the readiness refetch landed. Nulling it here forces
      // canEnableReset back to its safe default (false) for exactly that
      // window, matching "blocked until the new result arrives."
      setReadiness(null)
      show('Settings saved')
      setDirtySecrets(new Set())
      loadReadiness()
    } catch (e: any) {
      show(e.message, 'err')
    } finally {
      setSaving(false)
    }
  }

  return (
    <Shell>
      <PageHeader
        title="System Settings"
        subtitle="Email / SMTP configuration, scan retention and password reset"
        action={isAdmin ? <Button variant="primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button> : undefined}
      />
      {Toast}
      <div className="p-6 px-7 max-w-[600px]">
        <Card>
          <div className="px-6 py-5 flex flex-col gap-4">
            <section>
              <h3 className="text-style-caption mb-3">Email / SMTP</h3>
              {/*
                smtp_host is not locked while self-service reset is on, even
                though the feature depends on it (same reasoning as
                app_base_url below). The backend validates the *effective*
                (post-PATCH) value of both keys together
                (patch_settings' _effective()), so replacing this with
                another valid host in the same save that keeps the feature
                on is explicitly supported server-side — it only rejects a
                save that would leave the setting on with no usable host at
                all. Locking it forced disabling the feature first just to
                rotate mail providers, and disabling revokes every
                outstanding reset/welcome link (patch_settings' turning_off
                sweep) — an unrelated and unrecoverable side effect of what
                should be a one-field change. It also made the "Inactive —
                ... Restore them" message below impossible to follow when
                smtp_host was cleared externally while the flag stayed on:
                the recovery instruction told the admin to restore the
                setting this field refused to let them touch.
              */}
              <div className="flex flex-col gap-3">
                {KNOWN_SETTINGS.filter(s => s.key.startsWith('smtp_')).map(({ key, label, hint, type }) => (
                  <div key={key}>
                    {key === 'smtp_tls_mode' ? (
                      <Select label={label} value={settings[key] ?? ''} onChange={e => set(key, e.target.value)}>
                        <option value="">— none —</option>
                        <option value="none">none</option>
                        <option value="ssl">ssl</option>
                        <option value="starttls">starttls</option>
                      </Select>
                    ) : (
                      <Input
                        label={label}
                        type={type === 'secret' ? 'password' : type === 'int' ? 'number' : 'text'}
                        inputMode={type === 'int' ? 'numeric' : undefined}
                        placeholder={type === 'secret' && !dirtySecrets.has(key) ? '(saved — type to replace)' : hint}
                        value={settings[key] ?? ''}
                        onChange={e => set(key, e.target.value)}
                        autoComplete={type === 'secret' ? 'new-password' : undefined}
                      />
                    )}
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h3 className="text-style-caption mb-3">Scan Result Retention</h3>
              <div className="flex flex-col gap-3">
                {KNOWN_SETTINGS.filter(s => s.key.startsWith('scan_result_retention')).map(({ key, label, hint }) => (
                  <Input
                    key={key}
                    label={label}
                    type="number"
                    inputMode="numeric"
                    min={0}
                    placeholder={hint}
                    value={settings[key] ?? ''}
                    onChange={e => set(key, e.target.value)}
                  />
                ))}
              </div>
            </section>

            <section>
              <h3 className="text-style-caption mb-3">Findings / SLA</h3>
              <div className="flex flex-col gap-3">
                {KNOWN_SETTINGS.filter(s => s.key === 'sla_high_days' || s.key === 'sla_medium_days' || s.key === 'finding_retention_days').map(({ key, label, hint }) => (
                  <Input
                    key={key}
                    label={defaultKeys.has(key) ? `${label} (using default — not saved)` : label}
                    type="number"
                    inputMode="numeric"
                    min={1}
                    placeholder={hint}
                    value={settings[key] ?? ''}
                    onChange={e => set(key, e.target.value)}
                  />
                ))}
              </div>
            </section>

            <section>
              <h3 className="text-style-caption mb-3">Application</h3>
              <div className="flex flex-col gap-3">
                <Input
                  label="App Base URL"
                  placeholder="https://pa-central.example.com"
                  value={settings['app_base_url'] ?? ''}
                  onChange={e => set('app_base_url', e.target.value)}
                />
                {/*
                  Not locked while self-service reset is on, unlike smtp_host
                  above. The backend validates the *effective* (post-PATCH)
                  value of both keys together (patch_settings' _effective()),
                  so replacing this with another valid URL in the same save
                  that keeps the feature on is explicitly supported server-
                  side — it only rejects a save that would leave the setting
                  on with no usable base URL at all. Locking it here forced
                  disabling the feature first just to move the deployment to
                  a new address, and disabling revokes every outstanding
                  reset link (see patch_settings' turning_off sweep) — an
                  unrelated and unrecoverable side effect of what should be a
                  one-field change. It also fought the "Inactive" message
                  below, which tells the admin to restore a cleared
                  dependency while this field refused to let them.
                */}
                <TimezoneField
                  label="Default cron timezone"
                  value={settings['default_cron_timezone'] ?? ''}
                  onChange={v => set('default_cron_timezone', v)}
                  placeholder="leave blank for UTC"
                />
              </div>
            </section>

            <section>
              <h3 className="text-style-caption mb-3">Password Reset</h3>
              <div className="flex flex-col gap-1.5">
                <label className="flex items-center gap-2 text-xs text-foreground">
                  <input
                    type="checkbox"
                    checked={selfServiceOn}
                    // Only block turning it *on* while the backend reports it
                    // not ready. Turning it off must always be possible:
                    // disabling a checked box when a dependency breaks traps
                    // the admin, since the form still submits it as enabled
                    // and the save then fails with no way out.
                    disabled={!canEnableReset && !selfServiceOn}
                    onChange={e => set('self_service_password_reset', e.target.checked ? 'true' : 'false')}
                  />
                  Allow users to reset their own password by email
                </label>
                <span className="text-xs text-muted-foreground leading-relaxed">
                  {canEnableReset
                    ? 'Adds a "Forgot password?" link to the sign-in page. Admin-initiated resets email the user a link instead of generating a password.'
                    : selfServiceOn && hasUnsavedDependencyEdits
                      // Saved state is (or was) ready, but a dependency
                      // field has an unsaved edit since then — readiness
                      // only reflects what was last persisted, so it
                      // cannot yet know whether this edit fixes or breaks
                      // things. Saving with a field cleared here is what
                      // the "stays checked" design accepts as a real 400
                      // from the backend; naming it up front avoids that
                      // surprise.
                      ? 'Unsaved changes to the SMTP or App Base URL settings above — save them to confirm self-service reset still works, or the next save may be rejected.'
                      : selfServiceOn
                        // Still ticked, but the backend re-checks its
                        // dependencies at read time, so the flow is inactive —
                        // and saving in this state is rejected. The box stays
                        // operable so this is an instruction the admin can
                        // actually follow.
                        ? `Inactive — ${(readiness?.reasons ?? []).join(' ') || 'a required setting is missing or invalid.'} Restore the settings above, or untick this before saving.`
                        : hasUnsavedDependencyEdits
                          ? 'Save your SMTP and App Base URL changes above before enabling self-service reset.'
                          : (readiness?.reasons ?? []).join(' ')}
                </span>
              </div>
            </section>
          </div>
        </Card>
      </div>
    </Shell>
  )
}
