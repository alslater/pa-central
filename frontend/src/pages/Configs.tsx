import { useEffect, useRef, useState, useCallback } from 'react'
import { api, ConfigTemplate, Host, LintResult } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, Select, useToast, Empty, timeAgo } from '@/components/ui'
import { TomlEditor, validateToml } from '@/components/TomlEditor'
import { Plus, Trash2, Link, Star, RotateCcw } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

interface UseLintDebounceResult {
  lintResult: LintResult | null
  lintPending: boolean
  lintError: boolean
  runLint: (toml: string) => void
  setLintResult: (r: LintResult | null) => void
}

const LINT_DEBOUNCE_MS = 500  // fast enough to feel responsive, slow enough to avoid hammering on every keystroke

function useLintDebounce(): UseLintDebounceResult {
  const [lintResult, setLintResult] = useState<LintResult | null>(null)
  const [lintPending, setLintPending] = useState(false)
  const [lintError, setLintError] = useState(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const runLint = useCallback((toml: string) => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    abortRef.current?.abort()
    abortRef.current = null  // prevent the AbortError handler from clearing lintPending during debounce
    setLintPending(true)
    setLintError(false)
    debounceRef.current = setTimeout(() => {
      const controller = new AbortController()
      abortRef.current = controller
      api.configs.validate(toml, controller.signal)
        .then(r => {
          if (controller !== abortRef.current) return
          setLintResult(r); setLintPending(false); setLintError(false)
        })
        // On server error, keep lintResult so the save button can still use the last
        // known-good result. lintError=true shows the banner; the stale result is intentional.
        .catch(e => {
          if (e?.name === 'AbortError') {
            // Clear pending only when this was the latest request (unmount/navigation abort).
            // If a newer runLint already replaced abortRef, it owns pending state.
            if (controller === abortRef.current) setLintPending(false)
          } else {
            if (controller !== abortRef.current) return
            setLintPending(false)
            setLintError(true)
          }
        })
    }, LINT_DEBOUNCE_MS)
  }, [])
  useEffect(() => () => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    abortRef.current?.abort()
    // Null out so in-flight promise handlers fail the identity check and skip state updates.
    abortRef.current = null
  }, [])
  return { lintResult, lintPending, lintError, runLint, setLintResult }
}

function LintMessages({ result, lintError }: { result: LintResult | null; lintError?: boolean }) {
  const hasErrors = !!result && result.errors.length > 0
  const hasWarnings = !!result && result.warnings.length > 0
  if (!hasErrors && !hasWarnings && !lintError) return null
  return (
    <div aria-live="polite" aria-atomic="true">
      {lintError && (
        <div className="lint-warning-text">
          <span aria-hidden="true">⚠ </span>Server validation unavailable — syntax check only
        </div>
      )}
      {hasErrors && (
        <div role="alert">
          <ul aria-label="Validation errors" className={`lint-list${lintError ? ' mt-1' : ''}`}>
            {result!.errors.map((e, i) => (
              <li key={`${i}-${e}`} className="lint-error-text"><span aria-hidden="true">✕ </span>{e}</li>
            ))}
          </ul>
        </div>
      )}
      {hasWarnings && (
        <ul aria-label="Validation warnings" className={`lint-list${(hasErrors || lintError) ? ' mt-1' : ''}`}>
          {result!.warnings.map((w, i) => (
            <li key={`${i}-${w}`} className="lint-warning-text"><span aria-hidden="true">⚠ </span>{w}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

const DEFAULT_TOML = `# Fleet-managed package-alert configuration.
# [log], [cli_log], and [scheduler] are intentionally omitted — manage those per-host.

[osv]
cache_ttl_hours = 24
# base_url = "https://api.osv.dev/v1"
# timeout_seconds = 10.0
# max_retries = 3

[watch]
enable_cache_monitoring = true
enable_process_monitoring = true

[alerts]
desktop_notifications = false
terminal_notifications = true
min_severity_for_desktop = "MEDIUM"

[heuristics]
enabled = true
warning_threshold = 40
critical_threshold = 70
# top_packages_refresh_days = 7

# Risk score dampening — reduces false positives for well-established packages.
# high_dependent_count = 1000
# popularity_floor = 0.25
# max_damping_age_days = 90
# age_floor = 0.25
# combined_damping_floor = 0.1

[sandbox.cooldown]
period_days = 7
allow_cooldown_allow = false
# Action for packages within cooldown that match a typosquat pattern.
on_new_medium_risk = "prompt"
# Action for packages within cooldown with no typosquat match.
on_new_low_risk = "warn"
# In non-interactive contexts (CI, coding agents), escalate "prompt" to this.
non_interactive_escalation = "block"

# [sandbox]
# extra_env = []
# extra_tmpfs = []
# extra_ro_paths = []
# editable_roots = []
`

export default function Configs() {
  const [templates, setTemplates] = useState<ConfigTemplate[]>([])
  const [hosts, setHosts] = useState<Host[]>([])
  const [selected, setSelected] = useState<ConfigTemplate | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [showAssign, setShowAssign] = useState(false)
  // Inline edit state
  const [editToml, setEditToml] = useState<string | null>(null)
  const [editDesc, setEditDesc] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [loading, setLoading] = useState(true)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isOperator = user?.role === 'admin' || user?.role === 'operator'
  const isAdmin = user?.role === 'admin'

  const { lintResult, lintPending, lintError, runLint, setLintResult } = useLintDebounce()
  // lintError means the server is unavailable; the TOML syntax was still checked locally,
  // so allow save. Otherwise block on an explicit invalid result.
  const lintBlocksSave = !lintError && lintResult !== null && !lintResult.valid

  const load = useCallback(async () => {
    try {
      const myHosts = await api.hosts.list()
      setHosts(myHosts)
      if (isOperator) {
        const templates = await api.configs.list()
        setTemplates(templates)
      } else {
        // Developer: only show templates assigned to their own hosts
        const assigned = await Promise.all(myHosts.map(h => api.configs.forHost(h.id)))
        const unique = Object.values(
          Object.fromEntries(
            assigned.filter((t): t is ConfigTemplate => t !== null).map(t => [t.id, t])
          )
        )
        setTemplates(unique)
      }
    } catch (e: any) {
      show(e.message ?? 'Failed to load', 'err')
    } finally {
      setLoading(false)
    }
  }, [isOperator, show])
  useEffect(() => { load() }, [load]) // eslint-disable-line react-hooks/set-state-in-effect

  const selectTemplate = (t: ConfigTemplate) => {
    setSelected(t)
    setEditToml(null)
    setEditDesc(null)
    setLintResult(null)
    runLint(t.toml_content)
  }

  const discardEdits = () => {
    setEditToml(null)
    setEditDesc(null)
    if (selected) {
      setLintResult(null)
      runLint(selected.toml_content)
    }
  }

  const saveEdits = async () => {
    if (!selected) return
    setSaving(true)
    try {
      const updated = await api.configs.update(selected.id, {
        description: (editDesc ?? selected.description) || undefined,
        toml_content: editToml ?? selected.toml_content,
      })
      setTemplates(prev => prev.map(t => t.id === updated.id ? updated : t))
      setEditToml(null)
      setEditDesc(null)
      selectTemplate(updated)
      show('Template saved')
    } catch (e: any) {
      show(e.message, 'err')
    } finally {
      setSaving(false)
    }
  }

  const del = async (t: ConfigTemplate) => {
    if (!confirm(`Delete template "${t.name}"?`)) return
    await api.configs.delete(t.id).catch(e => show(e.message, 'err'))
    show('Template deleted'); setSelected(null); load()
  }

  const setDefault = async (t: ConfigTemplate) => {
    const updated = await api.configs.update(t.id, { is_default: true }).catch(e => { show(e.message, 'err'); return null })
    if (!updated) return
    setTemplates(prev => prev.map(tmpl => ({ ...tmpl, is_default: tmpl.id === t.id })))
    setSelected(updated)
    show(`"${t.name}" is now the default config`)
  }

  return (
    <Shell>
      <PageHeader
        title="Config templates"
        subtitle="TOML configurations to push to hosts"
        action={isOperator ? <Button variant="primary" onClick={() => setShowAdd(true)}><Plus size={13} />New template</Button> : undefined}
      />
      <div className="configs-layout">
        {/* List */}
        <div className="configs-list-col">
          {loading ? <div className="loading-text">Loading…</div> :
            templates.length === 0 ? <Empty message="No templates yet." /> : (
              <div className="configs-list-stack">
                {templates.map(t => (
                  <button key={t.id} type="button" onClick={() => selectTemplate(t)} className={`config-list-btn${selected?.id === t.id ? ' active' : ''}`}>
                    <div className="config-list-btn-name">
                      {t.name}
                      {t.is_default && <span className="badge-default">Default</span>}
                    </div>
                    {t.description && <div className="config-list-btn-desc">{t.description}</div>}
                    <div className="config-list-btn-meta">Updated {timeAgo(t.updated_at)}</div>
                  </button>
                ))}
              </div>
            )
          }
        </div>

        {/* Detail */}
        {selected && (() => {
          const isDirty = editToml !== null || editDesc !== null
          const currentToml = editToml ?? selected.toml_content
          const currentDesc = editDesc ?? (selected.description ?? '')
          const tomlInvalid = !!validateToml(currentToml)
          return (
            <Card className="config-detail-card">
              {/* Toolbar */}
              <div className="config-detail-toolbar">
                <div className="config-toolbar-name-col">
                  <div className="config-toolbar-name">
                    {selected.name}
                    {selected.is_default && <span className="badge-default">Default</span>}
                    {isDirty && <span className="badge-unsaved">Unsaved</span>}
                  </div>
                  {isOperator && (
                    <input
                      value={currentDesc}
                      onChange={e => setEditDesc(e.target.value)}
                      placeholder="Description"
                      className="config-desc-input"
                    />
                  )}
                  {!isOperator && selected.description && (
                    <div className="config-toml-label">{selected.description}</div>
                  )}
                </div>
                <div className="config-toolbar-actions">
                  {isDirty && (
                    <>
                      <Button variant="ghost" onClick={discardEdits}><RotateCcw size={13} />Discard</Button>
                      <Button variant="primary" onClick={saveEdits} disabled={tomlInvalid || saving || lintPending || lintBlocksSave}>{saving ? 'Saving…' : 'Save'}</Button>
                    </>
                  )}
                  {!isDirty && !selected.is_default && isOperator && (
                    <Button variant="secondary" onClick={() => setDefault(selected)}><Star size={13} />Set as default</Button>
                  )}
                  {isOperator && <Button variant="secondary" onClick={() => setShowAssign(true)}><Link size={13} />Assign to host</Button>}
                  {isAdmin && <Button variant="danger" onClick={() => del(selected)} title="Delete template" aria-label="Delete template"><Trash2 size={13} /></Button>}
                </div>
              </div>
              {/* Editor */}
              <div className="config-editor-section">
                <TomlEditor
                  value={currentToml}
                  onChange={isOperator ? (v) => { setEditToml(v); runLint(v) } : () => {}}
                  minHeight={400}
                  showError={isDirty}
                />
                {(lintResult || lintError) && (
                  <div className="lint-messages-padding">
                    <LintMessages result={lintResult} lintError={lintError} />
                  </div>
                )}
              </div>
            </Card>
          )
        })()}
      </div>

      {showAdd && (
        <AddTemplateModal
          onClose={() => setShowAdd(false)}
          onSaved={(t) => { load(); setShowAdd(false); selectTemplate(t); show('Template created') }}
        />
      )}

      {showAssign && selected && (
        <AssignModal
          template={selected} hosts={hosts}
          onClose={() => setShowAssign(false)}
          onSaved={() => { setShowAssign(false); show(`Assigned ${selected.name}`) }}
        />
      )}
      {Toast}
    </Shell>
  )
}

function AddTemplateModal({ onClose, onSaved }: { onClose: () => void; onSaved: (t: ConfigTemplate) => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [toml, setToml] = useState(DEFAULT_TOML)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const { lintResult, lintPending, lintError, runLint } = useLintDebounce()
  // lintError means the server is unavailable; the TOML syntax was still checked locally,
  // so allow save. Otherwise block on an explicit invalid result.
  const lintBlocksSave = !lintError && lintResult !== null && !lintResult.valid

  // Lint once on mount with the initial toml value. runLint is stable (useCallback([])).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { runLint(toml) }, [])

  const save = async () => {
    setSaving(true); setError('')
    try {
      const t = await api.configs.create({ name, description: description || undefined, toml_content: toml })
      onSaved(t)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal title="New config template" onClose={onClose}>
      <div className="modal-form">
        <Input label="Name *" value={name} onChange={e => setName(e.target.value)} placeholder="production-default" />
        <Input label="Description" value={description} onChange={e => setDescription(e.target.value)} />
        <div>
          <span className="config-toml-label">TOML content *</span>
          <div className="mt-1">
            <TomlEditor value={toml} onChange={v => { setToml(v); runLint(v) }} minHeight={300} />
          </div>
        </div>
        <LintMessages result={lintResult} lintError={lintError} />
        {error && <div className="lint-error-text">{error}</div>}
        <div className="modal-actions">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!name || !toml || !!validateToml(toml) || lintPending || lintBlocksSave || saving}>{saving ? 'Saving…' : 'Create'}</Button>
        </div>
      </div>
    </Modal>
  )
}


function AssignModal({ template, hosts, onClose, onSaved }: {
  template: ConfigTemplate; hosts: Host[]; onClose: () => void; onSaved: () => void
}) {
  const [hostId, setHostId] = useState('')
  const [saving, setSaving] = useState(false)

  const save = async () => {
    setSaving(true)
    await api.configs.assign(template.id, Number(hostId)).catch(console.error)
    onSaved()
    setSaving(false)
  }

  return (
    <Modal title={`Assign "${template.name}"`} onClose={onClose}>
      <div className="modal-form-sm">
        <Select label="Host" value={hostId} onChange={e => setHostId(e.target.value)}>
          <option value="">Select a host…</option>
          {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
        </Select>
        <div className="modal-actions">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!hostId || saving}>{saving ? 'Assigning…' : 'Assign'}</Button>
        </div>
      </div>
    </Modal>
  )
}
