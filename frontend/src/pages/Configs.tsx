import { useEffect, useState } from 'react'
import { api, ConfigTemplate, Host } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Card, Button, Input, Modal, Select, useToast, Empty, timeAgo } from '@/components/ui'
import { TomlEditor, validateToml } from '@/components/TomlEditor'
import { Plus, Trash2, Link, Star, RotateCcw } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'

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

  const load = async () => {
    const myHosts = await api.hosts.list()
    setHosts(myHosts)
    if (isOperator) {
      api.configs.list().then(setTemplates).finally(() => setLoading(false))
    } else {
      // Developer: only show templates assigned to their own hosts
      const assigned = await Promise.all(myHosts.map(h => api.configs.forHost(h.id)))
      const unique = Object.values(
        Object.fromEntries(
          assigned.filter((t): t is ConfigTemplate => t !== null).map(t => [t.id, t])
        )
      )
      setTemplates(unique)
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  const selectTemplate = (t: ConfigTemplate) => {
    setSelected(t)
    setEditToml(null)
    setEditDesc(null)
  }

  const discardEdits = () => { setEditToml(null); setEditDesc(null) }

  const saveEdits = async () => {
    if (!selected) return
    setSaving(true)
    try {
      const updated = await api.configs.update(selected.id, {
        description: (editDesc ?? selected.description) || undefined,
        toml_content: editToml ?? selected.toml_content,
      })
      setSelected(updated)
      setTemplates(prev => prev.map(t => t.id === updated.id ? updated : t))
      setEditToml(null)
      setEditDesc(null)
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
      <div style={{ padding: '24px 28px', overflow: 'auto', display: 'flex', gap: 16 }}>
        {/* List */}
        <div style={{ width: 260, flexShrink: 0 }}>
          {loading ? <div style={{ color: 'var(--text-muted)', fontSize: 13 }}>Loading…</div> :
            templates.length === 0 ? <Empty message="No templates yet." /> : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {templates.map(t => (
                  <button key={t.id} onClick={() => selectTemplate(t)} style={{
                    background: selected?.id === t.id ? 'var(--accent-dim)' : 'var(--bg-surface)',
                    border: `1px solid ${selected?.id === t.id ? 'var(--accent-border)' : 'var(--border)'}`,
                    borderRadius: 'var(--radius)', padding: '10px 14px', cursor: 'pointer',
                    textAlign: 'left', color: 'var(--text-primary)',
                  }}>
                    <div style={{ fontWeight: 500, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
                      {t.name}
                      {t.is_default && (
                        <span style={{
                          fontSize: 10, fontWeight: 600, padding: '1px 6px',
                          borderRadius: 3, background: 'rgba(56,139,253,0.15)',
                          color: '#388bfd', border: '1px solid rgba(56,139,253,0.3)',
                          letterSpacing: '0.04em', textTransform: 'uppercase' as const,
                        }}>Default</span>
                      )}
                    </div>
                    {t.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{t.description}</div>}
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>Updated {timeAgo(t.updated_at)}</div>
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
            <Card style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
              {/* Toolbar */}
              <div style={{ padding: '10px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
                    {selected.name}
                    {selected.is_default && (
                      <span style={{ fontSize: 10, fontWeight: 600, padding: '1px 6px', borderRadius: 3, background: 'hsl(var(--status-info)/0.15)', color: 'hsl(var(--status-info-text))', border: '1px solid hsl(var(--status-info)/0.3)', letterSpacing: '0.04em', textTransform: 'uppercase' as const }}>Default</span>
                    )}
                    {isDirty && (
                      <span style={{ fontSize: 10, fontWeight: 600, padding: '1px 6px', borderRadius: 3, background: 'hsl(var(--status-review)/0.15)', color: 'hsl(var(--status-review-text))', border: '1px solid hsl(var(--status-review)/0.3)', letterSpacing: '0.04em', textTransform: 'uppercase' as const }}>Unsaved</span>
                    )}
                  </div>
                  {isOperator && (
                    <input
                      value={currentDesc}
                      onChange={e => setEditDesc(e.target.value)}
                      placeholder="Description"
                      style={{ fontSize: 12, color: 'var(--text-secondary)', background: 'transparent', border: 'none', outline: 'none', fontFamily: 'var(--font-ui)', width: '100%' }}
                    />
                  )}
                  {!isOperator && selected.description && (
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{selected.description}</div>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
                  {isDirty && (
                    <>
                      <Button variant="ghost" onClick={discardEdits}><RotateCcw size={13} />Discard</Button>
                      <Button variant="primary" onClick={saveEdits} disabled={tomlInvalid || saving}>{saving ? 'Saving…' : 'Save'}</Button>
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
              <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                <TomlEditor
                  value={currentToml}
                  onChange={isOperator ? (v) => setEditToml(v) : () => {}}
                  minHeight={400}
                  showError={isDirty}
                />
              </div>
            </Card>
          )
        })()}
      </div>

      {showAdd && (
        <AddTemplateModal
          onClose={() => setShowAdd(false)}
          onSaved={(t) => { load(); setShowAdd(false); setSelected(t); show('Template created') }}
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
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <Input label="Name *" value={name} onChange={e => setName(e.target.value)} placeholder="production-default" />
        <Input label="Description" value={description} onChange={e => setDescription(e.target.value)} />
        <div>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>TOML content *</span>
          <div style={{ marginTop: 4 }}>
            <TomlEditor value={toml} onChange={setToml} minHeight={300} />
          </div>
        </div>
        {error && <div style={{ color: 'var(--err)', fontSize: 12 }}>{error}</div>}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!name || !toml || !!validateToml(toml) || saving}>{saving ? 'Saving…' : 'Create'}</Button>
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
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <Select label="Host" value={hostId} onChange={e => setHostId(e.target.value)}>
          <option value="">Select a host…</option>
          {hosts.map(h => <option key={h.id} value={h.id}>{h.name}</option>)}
        </Select>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={!hostId || saving}>{saving ? 'Assigning…' : 'Assign'}</Button>
        </div>
      </div>
    </Modal>
  )
}
