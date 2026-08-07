import React, { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react'
import {
  api, RepoScan, RepoScanResult, RepoCredential, ConfigTemplate, AlertSeverity, CredentialType, ScanFlag, ScanOptions, FindingRecord,
} from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { useAuth } from '@/hooks/useAuth'
import { Card, Button, Drawer, FindingAcceptForm, FindingRecordDetail, FindingRevokeButton, Input, Select, Modal, useToast, Empty, RepoScanStatusBadge, FindingsTable, SeverityBadge, timeAgo } from '@/components/ui'
import { Plus, Trash2, Play, ChevronDown, ChevronUp, RefreshCw, KeyRound, Settings2 } from 'lucide-react'
import { CronField } from '@/components/CronField'
import { TimezoneField } from '@/components/TimezoneField'
import { parseScanArgs, assembleScanArgs, compileFlags, scanArgsReducer } from '@/lib/scanArgs'
import { useRovingTabs } from '@/lib/hooks'

const SEV_OPTIONS: AlertSeverity[] = ['info', 'low', 'warning', 'medium', 'high', 'critical']
const CRED_OPTIONS: CredentialType[] = ['none', 'https_token', 'ssh_key']

// Normalises a pasted PEM key into the canonical RFC 7468 layout that OpenSSH
// and most TLS libraries require: header line, optional Proc-Type/DEK-Info
// lines (for encrypted keys), a blank separator, 64-char-wrapped base64 body,
// then footer line.
//
// The pre-split keyword newline insertion (the `between.replace(…)` call
// below) is load-bearing: pasted keys sometimes arrive with PEM headers
// fused directly to the preceding value with no whitespace
// (e.g. "4,ENCRYPTEDDEK-Info:AES-128-CBC,..."), which would cause the header
// keyword to be missed by the per-line matcher and treated as body data,
// corrupting the key. Inserting '\n' before each keyword before splitting
// guarantees they are on their own line.
//
// DEK-Info is matched precisely (ALGO,HEXIV) so that any base64 body chars
// that trail immediately after the IV without whitespace are captured in
// group 2 and routed to bodyParts rather than lost.
function normalizePem(value: string): string {
  const headerMatch = value.match(/^(-----BEGIN [^-]+-----)/)
  const footerMatch = value.match(/(-----END [^-]+-----)/)
  if (!headerMatch || !footerMatch) return value
  let between = value.slice(headerMatch[0].length, value.indexOf(footerMatch[0])).trim()
  // Insert newlines before known header keywords before splitting, so tokens like
  // "4,ENCRYPTEDDEK-Info:" (no space between Proc-Type value and next header) are separated.
  between = between.replace(/(Proc-Type|DEK-Info)\s*:/g, '\n$1:')
  const pemHeaders: string[] = []
  const bodyParts: string[] = []
  for (const line of between.split('\n')) {
    const t = line.trim()
    if (!t) continue
    const procType = t.match(/^Proc-Type:\s*(\S+)(.*)/)
    // DEK-Info value is ALGO,HEXIV — match the IV precisely so body chars fused to it are separated
    const dekInfo  = t.match(/^DEK-Info:\s*([A-Z0-9-]+,[0-9A-Fa-f]+)(.*)/)

    if (procType) {
      pemHeaders.push(`Proc-Type: ${procType[1]}`)
      if (procType[2]) bodyParts.push(procType[2].replace(/\s+/g, ''))
    } else if (dekInfo) {
      pemHeaders.push(`DEK-Info: ${dekInfo[1]}`)
      if (dekInfo[2]) bodyParts.push(dekInfo[2].replace(/\s+/g, ''))
    } else {
      bodyParts.push(t.replace(/\s+/g, ''))
    }
  }
  const body = bodyParts.join('')
  const wrapped = body.match(/.{1,64}/g)?.join('\n') ?? body
  const lines = [headerMatch[0], ...pemHeaders, ...(pemHeaders.length ? [''] : []), wrapped, footerMatch[0]]
  return lines.join('\n')
}

// ── Credentials section ────────────────────────────────────────────────────────

function CredentialForm({
  initial, onSave, onCancel,
}: {
  initial?: RepoCredential
  onSave: (data: { name: string; credential_type: CredentialType; credential_value?: string; ssh_key_passphrase?: string }) => void
  onCancel: () => void
}) {
  const [form, setForm] = useState({
    name: initial?.name ?? '',
    credential_type: initial?.credential_type ?? 'none' as CredentialType,
    credential_value: '',
    ssh_key_passphrase: '',
  })
  const set = (k: string, v: unknown) => setForm(prev => ({ ...prev, [k]: v }))

  const submit = () => {
    if (!form.name) return
    onSave({
      name: form.name,
      credential_type: form.credential_type,
      credential_value: form.credential_value || undefined,
      ssh_key_passphrase: (form.credential_type === 'ssh_key' && form.ssh_key_passphrase) ? form.ssh_key_passphrase : undefined,
    })
  }

  return (
    <div className="cred-form-grid-wrap">
      <div className="cred-form-grid">
        <Input label="Name" value={form.name} onChange={e => set('name', e.target.value)} />
        <Select label="Type" value={form.credential_type} onChange={e => set('credential_type', e.target.value)}>
          {CRED_OPTIONS.map(c => <option key={c} value={c}>{c}</option>)}
        </Select>
        {form.credential_type !== 'none' && (
          <Input
            label={form.credential_type === 'ssh_key' ? 'SSH private key' : 'HTTPS token'}
            type="password"
            placeholder={initial ? 'Leave blank to keep existing' : undefined}
            value={form.credential_value}
            onChange={e => set('credential_value', form.credential_type === 'ssh_key' ? normalizePem(e.target.value) : e.target.value)}
          />
        )}
        {form.credential_type === 'ssh_key' && (
          <Input
            label="Passphrase (if protected)"
            type="password"
            placeholder="Leave blank if none"
            value={form.ssh_key_passphrase}
            onChange={e => set('ssh_key_passphrase', e.target.value)}
          />
        )}
      </div>
      <div className="cred-form-actions">
        <Button variant="primary" onClick={submit}>{initial ? 'Save' : 'Add'}</Button>
        <Button variant="secondary" onClick={onCancel}>Cancel</Button>
      </div>
    </div>
  )
}

function CredentialsPanel({
  credentials, isOperator, isAdmin, onEdit, onDelete,
}: {
  credentials: RepoCredential[]
  isOperator: boolean
  isAdmin: boolean
  onEdit: (id: number, data: Parameters<typeof api.repoCredentials.update>[1]) => void
  onDelete: (cred: RepoCredential) => void
}) {
  const [editingId, setEditingId] = useState<number | null>(null)

  const CRED_TYPE_LABEL: Record<CredentialType, string> = {
    none: 'None', https_token: 'HTTPS token', ssh_key: 'SSH key',
  }

  return (
    <Card className="card-mb-24">
      <div className="cred-panel-header">
        <KeyRound size={14} className="text-muted" />
        <span className="cred-panel-title">Credentials</span>
        <span className="cred-panel-subtext">shared across repo scans</span>
      </div>

      {credentials.length === 0 ? (
        <div className="cred-empty-wrap">
          <Empty message="No credentials yet. Add one to use with repo scans." />
        </div>
      ) : (
        credentials.map(cred => (
          <div key={cred.id}>
            <div className="cred-row">
              <span className="cred-name">{cred.name}</span>
              <span className="cred-type-badge">{CRED_TYPE_LABEL[cred.credential_type]}</span>
              {isAdmin && (
                <Button variant="ghost" onClick={() => onDelete(cred)} className="delete-btn-color px-2 py-1" title={`Delete ${cred.name}`} aria-label={`Delete ${cred.name}`}>
                  <Trash2 size={12} />
                </Button>
              )}
              {isOperator && (
                <Button variant="ghost" onClick={() => setEditingId(editingId === cred.id ? null : cred.id)} className="px-2 py-1" title={editingId === cred.id ? 'Collapse credential' : 'Edit credential'} aria-label={editingId === cred.id ? 'Collapse credential' : 'Edit credential'}>
                  {editingId === cred.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                </Button>
              )}
            </div>
            {editingId === cred.id && (
              <div className="cred-edit-section">
                <CredentialForm
                  initial={cred}
                  onSave={data => { onEdit(cred.id, data); setEditingId(null) }}
                  onCancel={() => setEditingId(null)}
                />
              </div>
            )}
          </div>
        ))
      )}
    </Card>
  )
}

// ── Scan results ───────────────────────────────────────────────────────────────

function ResultsPanel({ scan, refreshKey }: { scan: RepoScan; refreshKey?: number }) {
  const [results, setResults] = useState<RepoScanResult[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [expandedId, setExpandedId] = useState<number | null>(null)

  const load = useCallback((indicator: 'initial' | 'refresh') => {
    if (indicator === 'initial') setLoading(true)
    else setRefreshing(true)
    api.repoScans.results(scan.id).then(setResults).finally(() => {
      setLoading(false)
      setRefreshing(false)
    })
  }, [scan.id])
  useEffect(() => { load('initial') }, [load]) // eslint-disable-line react-hooks/set-state-in-effect
  useEffect(() => { if (refreshKey) load('refresh') }, [load, refreshKey]) // eslint-disable-line react-hooks/set-state-in-effect

  if (loading) return <div className="loading-text-sm">Loading…</div>

  return (
    <div>
      <div className="result-refresh-row">
        <Button variant="ghost" onClick={() => load('refresh')} title="Refresh results" aria-label="Refresh results" className="px-2 py-1">
          <RefreshCw size={14} className={refreshing ? 'animate-spin' : undefined} />
        </Button>
      </div>
      {results.length === 0 ? (
        <div className="result-empty-wrap"><Empty message="No scan results yet" /></div>
      ) : results.map(r => {
        const hasFindings = r.findings && r.findings.length > 0
        const isExpanded = expandedId === r.id
        return (
          <div key={r.id} className="result-row">
            <div
              className={`result-row-content ${hasFindings ? 'result-row-clickable' : 'result-row-static'}`}
              onClick={() => hasFindings && setExpandedId(isExpanded ? null : r.id)}
              onKeyDown={e => { if (hasFindings && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); setExpandedId(isExpanded ? null : r.id) } }}
              role={hasFindings ? 'button' : undefined}
              tabIndex={hasFindings ? 0 : undefined}
              aria-expanded={hasFindings ? isExpanded : undefined}
            >
              <RepoScanStatusBadge status={r.status} />
              <span className="result-trigger-label">
                {r.triggered_by === 'scheduled' ? '⏱ scheduled' : '▶ manual'}
              </span>
              {r.finding_count != null && (
                <span className={`result-finding-count ${r.finding_count > 0 ? 'has-findings' : 'no-findings'}`}>
                  {r.finding_count} finding{r.finding_count !== 1 ? 's' : ''}
                </span>
              )}
              {r.pa_version && (
                <span className="result-pa-version">pa@{r.pa_version}</span>
              )}
              <span className="result-timestamp">
                {r.started_at ? timeAgo(r.started_at) : ''}
              </span>
              {hasFindings && (
                <span className="result-chevron">
                  {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                </span>
              )}
            </div>
            {r.sources && r.sources.length > 0 && (
              <div className="result-sources-row">
                <span className="result-sources-label">Sources</span>
                {r.sources.map(src => (
                  <span key={src} className="result-source-tag">{src}</span>
                ))}
              </div>
            )}
            {r.error_message && (
              <pre className="result-error-pre">{r.error_message}</pre>
            )}
            {isExpanded && hasFindings && (
              <div className="result-findings-expanded">
                <FindingsTable findings={r.findings!} />
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Findings panel ─────────────────────────────────────────────────────────────

function FindingDetailDrawer({ f, onClose, onAccepted, show }: { f: FindingRecord; onClose: () => void; onAccepted: () => void; show: (msg: string, kind: 'ok' | 'err') => void }) {
  const [accepting, setAccepting] = React.useState(false)

  return (
    <Drawer title={`${f.package} — ${f.advisory_id}`} onClose={onClose}>
      <FindingRecordDetail f={f}>
        <div className="mt-4 pt-4 border-t border-border">
          {f.is_accepted ? (
            <FindingRevokeButton finding={f} onDone={onAccepted} show={show} />
          ) : accepting ? (
            <FindingAcceptForm
              finding={f}
              onDone={() => { setAccepting(false); onAccepted() }}
              onCancel={() => setAccepting(false)}
              show={show}
            />
          ) : (
            <Button variant="secondary" onClick={() => setAccepting(true)} className="text-[12px] px-3 h-8">Accept finding</Button>
          )}
        </div>
      </FindingRecordDetail>
    </Drawer>
  )
}

function FindingsPanel({ scanId, show }: { scanId: number; show: (msg: string, kind: 'ok' | 'err') => void }) {
  const [findings, setFindings] = React.useState<FindingRecord[] | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [loadError, setLoadError] = React.useState(false)
  const [selected, setSelected] = React.useState<FindingRecord | null>(null)

  const reqSeq = React.useRef(0)

  const reload = React.useCallback((background = false) => {
    const seq = ++reqSeq.current
    setLoadError(false)
    if (!background) { setLoading(true); setFindings(null) }
    api.findings.listAllForRepo(scanId).then(data => {
      if (seq !== reqSeq.current) return
      setFindings(data)
      setLoading(false)
      setSelected(prev => prev ? data.find(f => f.id === prev.id) ?? null : null)
    }).catch((e: Error) => {
      if (seq !== reqSeq.current) return
      setLoading(false)
      if (!background) setLoadError(true)
      show(e.message ?? 'Failed to load findings', 'err')
    })
  }, [scanId, show])

  React.useEffect(() => {
    reload() // eslint-disable-line react-hooks/set-state-in-effect
    // reqSeq is an abort counter: incrementing it in cleanup is intentional — it invalidates
    // any in-flight response from the previous render so stale data is never committed.
    return () => { reqSeq.current++ } // eslint-disable-line react-hooks/exhaustive-deps
  }, [reload])

  if (loading && !findings) return <div className="p-3 text-[13px] text-muted-foreground">Loading findings…</div>
  if (loadError) return (
    <div className="p-3 text-[13px] text-status-fail-text flex items-center gap-2">
      Failed to load findings.
      <button type="button" onClick={() => reload()} className="underline hover:no-underline">Retry</button>
    </div>
  )
  const rows = findings ?? []
  if (rows.length === 0) return <div className="px-4 py-2"><Empty message="No open findings." /></div>

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[12px]">
          <thead>
            <tr className="text-left border-b border-border">
              <th scope="col" className="px-4 py-2 text-style-caption">Severity</th>
              <th scope="col" className="px-4 py-2 text-style-caption">Package</th>
              <th scope="col" className="px-4 py-2 text-style-caption">Ecosystem</th>
              <th scope="col" className="px-4 py-2 text-style-caption">Advisory</th>
              <th scope="col" className="px-4 py-2 text-style-caption">Open since</th>
              <th scope="col" className="px-4 py-2 text-style-caption">SLA</th>
              <th scope="col" className="px-4 py-2 text-style-caption">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(f => (
              <tr
                key={f.id}
                className="border-b border-border/50 hover:bg-muted/40 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand"
                tabIndex={0}
                role="button"
                aria-label={`${f.package} ${f.advisory_id} — view details`}
                onClick={() => setSelected(f)}
                onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(f) } }}
              >
                <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
                <td className="px-4 py-2 font-mono">
                  {f.package}
                  {f.reopen_count > 0 && (
                    <span className="ml-1.5 text-[11px] text-status-review-text">↩×{f.reopen_count}</span>
                  )}
                </td>
                <td className="px-4 py-2 text-muted-foreground">{f.ecosystem}</td>
                <td className="px-4 py-2 font-mono text-muted-foreground">{f.advisory_id}</td>
                <td className={`px-4 py-2 font-medium ${f.in_breach ? 'text-status-fail-text' : 'text-muted-foreground'}`}>{f.days_open}d</td>
                <td className="px-4 py-2 text-muted-foreground">{f.sla_days ? `${f.sla_days}d` : '—'}</td>
                <td className="px-4 py-2">
                  {f.is_accepted ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-info/12 text-status-info-text" title={f.accepted_reason ?? undefined}>Accepted</span>
                  ) : f.in_breach ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-fail/12 text-status-fail-text">Breaching</span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-muted text-muted-foreground">Open</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && (
        <FindingDetailDrawer
          f={selected}
          onClose={() => setSelected(null)}
          onAccepted={() => { reload(true); setSelected(null) }}
          show={show}
        />
      )}
    </>
  )
}

// ── Structured scan args field ────────────────────────────────────────────────
//
// UNCONTROLLED after mount: defaultScanFlags seeds state once via the lazy
// useReducer initializer, then the component owns bools/strs internally.
// To reset from outside, change the key prop (e.g. key={scan.id}) — that
// remounts the component and re-runs the initializer. Do NOT add a sync
// effect that writes into bools/strs; it would fight user edits.
//
// onChange is stored in a ref so the emission effect doesn't need it as a
// dependency — passing an inline lambda would otherwise re-run the effect on
// every parent render.
//
// lastEmittedRef suppresses a spurious onChange call on mount (the initial
// assembled value matches the seed) and no-op emissions when the user
// toggles flags back to their original state.

function ScanArgsField({
  options,
  defaultScanFlags,
  onChange,
}: {
  options: ScanOptions
  /** One-time seed. To reset from outside, remount via a changed key prop. */
  defaultScanFlags: string
  onChange: (assembled: string) => void
}) {
  const compiledFlags = useMemo(() => compileFlags(options.flags), [options.flags])

  const [{ bools, strs }, dispatch] = useReducer(
    scanArgsReducer,
    { defaultScanFlags, compiledFlags },
    ({ defaultScanFlags, compiledFlags }) => parseScanArgs(defaultScanFlags, compiledFlags),
  )

  const flagByName = useMemo(
    () => new Map(options.flags.map((f: ScanFlag) => [f.name, f])),
    [options.flags],
  )

  // onChange is mirrored so the emit effect below doesn't re-run when the
  // parent passes a new callback identity. Written in an effect, not during
  // render: a discarded or replayed render must not mutate the ref. Declared
  // before the emit effect, so it commits first and the emit reads the current
  // callback. React 19: replace with useEffectEvent.
  const onChangeRef = useRef(onChange)
  useEffect(() => { onChangeRef.current = onChange }, [onChange])

  const lastEmittedRef = useRef(assembleScanArgs(bools, strs, options.flags))

  useEffect(() => {
    const assembled = assembleScanArgs(bools, strs, options.flags)
    if (assembled === lastEmittedRef.current) return
    lastEmittedRef.current = assembled
    onChangeRef.current(assembled)
  }, [bools, strs, options.flags])

  const isExcluded = (flagName: string) => {
    for (const pair of options.exclusions) {
      if (!pair.includes(flagName)) continue
      const other = pair.find(p => p !== flagName)
      if (!other) continue
      const otherFlag = flagByName.get(other)
      if (!otherFlag) continue
      if (otherFlag.type === 'bool' && bools[other]) return true
      if (otherFlag.type === 'str' && other in strs) return true
    }
    return false
  }

  const toggleBool = (name: string) => {
    dispatch({ type: 'toggle_bool', name, exclusions: options.exclusions, flagByName })
  }

  const setStr = (name: string, val: string) => {
    dispatch({ type: 'set_str', name, val, exclusions: options.exclusions, flagByName })
  }

  return (
    <div className="scan-args-wrap">
      <span className="scan-options-label">Scan options</span>
      {options.flags.map((flag: ScanFlag) => {
        const excluded = isExcluded(flag.name)
        if (flag.type === 'bool') {
          return (
            <div key={flag.name} className={`scan-flag-wrap${excluded ? ' excluded' : ''}`}>
              <label className="scan-flag-bool-label">
                <input
                  type="checkbox"
                  checked={!!bools[flag.name]}
                  disabled={excluded}
                  onChange={() => toggleBool(flag.name)}
                />
                <span>{flag.cli_flag}</span>
              </label>
              {flag.help && <div className="scan-flag-help-indented">{flag.help}</div>}
            </div>
          )
        }
        return (
          <div key={flag.name} className={`scan-flag-wrap${excluded ? ' excluded' : ''}`}>
            <Input
              label={flag.cli_flag}
              value={strs[flag.name] ?? ''}
              disabled={excluded}
              onChange={e => setStr(flag.name, e.target.value)}
              placeholder={flag.help}
            />
            {flag.help && <div className="scan-flag-help">{flag.help}</div>}
          </div>
        )
      })}
    </div>
  )
}

// ── Scan card / edit form ──────────────────────────────────────────────────────

function ScanCard({
  scan, credentials, templates, defaultTz, scanOptions, scanOptionsVersion, isOperator, isAdmin, onUpdate, onDelete, onTrigger, show,
}: {
  scan: RepoScan
  credentials: RepoCredential[]
  templates: ConfigTemplate[]
  defaultTz: string | null
  scanOptions: ScanOptions | null
  scanOptionsVersion: number
  isOperator: boolean
  isAdmin: boolean
  onUpdate: (id: number, patch: Partial<RepoScan>) => void
  onDelete: (scan: RepoScan) => void
  onTrigger: (scan: RepoScan) => Promise<void>
  show: (msg: string, kind: 'ok' | 'err') => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [expandedTab, setExpandedTab] = useState<'results' | 'findings'>('results')
  const [editing, setEditing] = useState(false)
  const [latestStatus, setLatestStatus] = useState<RepoScanResult['status'] | null>(null)
  const [resultsRefreshKey, setResultsRefreshKey] = useState(0)
  const pollingRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const triggeredAtRef = useRef<number | null>(null)
  const latestStatusRef = useRef<RepoScanResult['status'] | null>(null)
  const credName = credentials.find(c => c.id === scan.credential_id)?.name

  const startPolling = () => {
    triggeredAtRef.current = Date.now()
    if (pollingRef.current) clearTimeout(pollingRef.current)
    const poll = () => {
      api.repoScans.results(scan.id).then(results => {
        const top = results[0] ?? null
        const resultTime = top?.started_at ? new Date(top.started_at + 'Z').getTime() : 0
        if (triggeredAtRef.current && resultTime < triggeredAtRef.current - 5000) {
          pollingRef.current = setTimeout(poll, 2000)
          return
        }
        const wasRunning = latestStatusRef.current === 'running' || latestStatusRef.current === 'pending'
        latestStatusRef.current = top?.status ?? null
        setLatestStatus(top?.status ?? null)
        if (top?.status === 'running' || top?.status === 'pending') {
          pollingRef.current = setTimeout(poll, 2000)
        } else {
          pollingRef.current = null
          if (wasRunning) setResultsRefreshKey(k => k + 1)
        }
      }).catch(() => {})
    }
    poll()
  }

  useEffect(() => {
    return () => { if (pollingRef.current) clearTimeout(pollingRef.current) }
  }, [])

  const dotColor = latestStatus === 'running' || latestStatus === 'pending'
    ? '#79c0ff'
    : latestStatus === 'failed'
    ? '#f85149'
    : scan.is_enabled ? '#3fb950' : '#8b949e'
  const isRunning = latestStatus === 'running' || latestStatus === 'pending'

  return (
    <Card className="card-mb-12">
      <div className="scan-card-header">
        <div
          className={`scan-status-dot${isRunning ? ' running' : ''}`}
          style={{ background: dotColor, boxShadow: `0 0 6px ${dotColor}` }}
        />
        <div className="scan-card-info">
          <div className="scan-card-name-row">
            {scan.name}
            {scan.breach && (
              <button
                type="button"
                className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-status-fail/12 text-status-fail-text cursor-pointer shrink-0 border-none"
                onClick={() => { setExpanded(true); setExpandedTab('findings') }}
                title={`${scan.breach_count} finding${scan.breach_count !== 1 ? 's' : ''} breaching SLA`}
                aria-label={`${scan.breach_count} finding${scan.breach_count !== 1 ? 's' : ''} breaching SLA — view findings`}
              >
                SLA breach ×{scan.breach_count}
              </button>
            )}
          </div>
          <div className="scan-card-meta">
            {scan.url} · {scan.branch}
            {credName && <> · <KeyRound size={10} className="icon-inline" /> {credName}</>}
            {scan.cron_schedule && <> · <code className="font-mono">{scan.cron_schedule}</code></>}
          </div>
        </div>
        <div className="scan-card-actions">
          {scan.last_scan_at && (
            <span className="scan-card-last-scan">last: {timeAgo(scan.last_scan_at)}</span>
          )}
          {isOperator && (
            <Button variant="ghost" disabled={!scan.is_enabled} onClick={() => onTrigger(scan).then(() => { latestStatusRef.current = 'running'; setLatestStatus('running'); startPolling() })} className={`px-2 py-1${scan.is_enabled ? '' : ' opacity-35'}`} title={`Trigger ${scan.name}`} aria-label={`Trigger ${scan.name}`}>
              <Play size={12} />
            </Button>
          )}
          {isOperator && (
            <Button variant="ghost" onClick={() => setEditing(x => !x)} className={`px-2 py-1${editing ? ' text-secondary' : ''}`} title={`${editing ? 'Close' : 'Open'} settings for ${scan.name}`} aria-label={`${editing ? 'Close' : 'Open'} settings for ${scan.name}`}>
              <Settings2 size={12} />
            </Button>
          )}
          {isAdmin && (
            <Button variant="ghost" onClick={() => onDelete(scan)} className="px-2 py-1 delete-btn-color" title={`Delete ${scan.name}`} aria-label={`Delete ${scan.name}`}>
              <Trash2 size={12} />
            </Button>
          )}
          <Button variant="ghost" onClick={() => setExpanded(x => !x)} className="px-2 py-1" title={expanded ? 'Collapse results' : 'Expand results'} aria-label={expanded ? 'Collapse results' : 'Expand results'}>
            {expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </Button>
        </div>
      </div>

      {editing && isOperator && (
        <div className="form-section-border">
          <EditForm scan={scan} credentials={credentials} templates={templates} defaultTz={defaultTz} scanOptions={scanOptions} scanOptionsVersion={scanOptionsVersion} onSave={patch => { onUpdate(scan.id, patch); setEditing(false) }} />
        </div>
      )}

      {expanded && (
        <div className="form-section-border">
          <div className="scan-card-inner-tab-bar">
            {(['results', 'findings'] as const).map(t => (
              <button
                key={t}
                type="button"
                onClick={() => setExpandedTab(t)}
                className={expandedTab === t ? 'tab-btn-inner active' : 'tab-btn-inner'}
              >
                {t === 'results' ? 'Results' : 'Findings'}
                {t === 'findings' && scan.breach_count > 0 && (
                  <span className="inner-tab-breach-badge">{scan.breach_count}</span>
                )}
              </button>
            ))}
          </div>
          {expandedTab === 'results' ? (
            <ResultsPanel scan={scan} refreshKey={resultsRefreshKey} />
          ) : (
            <FindingsPanel scanId={scan.id} show={show} />
          )}
        </div>
      )}
    </Card>
  )
}


function EditForm({
  scan, credentials, templates, defaultTz, scanOptions, scanOptionsVersion, onSave,
}: {
  scan: RepoScan
  credentials: RepoCredential[]
  templates: ConfigTemplate[]
  defaultTz: string | null
  scanOptions: ScanOptions | null
  scanOptionsVersion: number
  onSave: (patch: Partial<RepoScan>) => void
}) {
  const [form, setForm] = useState({
    name: scan.name,
    url: scan.url,
    branch: scan.branch,
    cron_schedule: scan.cron_schedule ?? '',
    cron_timezone: scan.cron_timezone ?? '',
    is_enabled: scan.is_enabled,
    credential_id: scan.credential_id ?? '',
    config_template_id: scan.config_template_id ?? '',
    pa_version: scan.pa_version ?? '',
    scan_flags: scan.scan_flags ?? '',
    subfolder: scan.subfolder ?? '',
    sla_high_days: scan.sla_high_days ?? null,
    sla_medium_days: scan.sla_medium_days ?? null,
    min_notify_severity: scan.min_notify_severity,
    notify_recipients: (scan.notify_recipients ?? []).join(', '),
  })

  const set = (k: string, v: unknown) => setForm(prev => ({ ...prev, [k]: v }))

  const [confirmOpen, setConfirmOpen] = React.useState(false)
  const [pendingPatch, setPendingPatch] = React.useState<Partial<RepoScan> | null>(null)

  const buildPatch = (): Partial<RepoScan> => ({
    name: form.name,
    url: form.url,
    branch: form.branch,
    cron_schedule: form.cron_schedule || null,
    cron_timezone: form.cron_timezone || null,
    is_enabled: form.is_enabled,
    credential_id: form.credential_id ? Number(form.credential_id) : null,
    config_template_id: form.config_template_id ? Number(form.config_template_id) : null,
    pa_version: form.pa_version || null,
    scan_flags: form.scan_flags || null,
    subfolder: form.subfolder || null,
    sla_high_days: form.sla_high_days,
    sla_medium_days: form.sla_medium_days,
    min_notify_severity: form.min_notify_severity as AlertSeverity,
    notify_recipients: form.notify_recipients.split(',').map((s: string) => s.trim()).filter(Boolean),
  })

  const configChanged = (): boolean => {
    const scanFlagsChanged = (form.scan_flags || null) !== scan.scan_flags
    const subfolderChanged = (form.subfolder || null) !== scan.subfolder
    const templateChanged = (form.config_template_id ? Number(form.config_template_id) : null) !== scan.config_template_id
    return scanFlagsChanged || subfolderChanged || templateChanged
  }

  const submit = () => {
    const patch = buildPatch()
    if (configChanged()) {
      setPendingPatch(patch)
      setConfirmOpen(true)
    } else {
      onSave(patch)
    }
  }

  return (
    <div className="edit-form-wrap">
      <div className="edit-form-grid">
        <Input label="Name" value={form.name} onChange={e => set('name', e.target.value)} />
        <Input label="URL" value={form.url} onChange={e => set('url', e.target.value)} />
        <Input label="Branch" value={form.branch} onChange={e => set('branch', e.target.value)} />
        <div className="edit-form-span2">
          <CronField value={form.cron_schedule} onChange={v => set('cron_schedule', v)} timezone={form.cron_timezone || defaultTz} />
        </div>
        <TimezoneField value={form.cron_timezone} onChange={v => set('cron_timezone', v)} placeholder={`default: ${defaultTz ?? 'UTC'}`} />
        <Input label="PA version" placeholder="latest" value={form.pa_version} onChange={e => set('pa_version', e.target.value)} />
        <Input label="Subfolder" placeholder="e.g. backend (leave blank to scan repo root)" value={form.subfolder} onChange={e => set('subfolder', e.target.value)} />
        <Input
          label="SLA: High/Critical (days)"
          type="number"
          min={1}
          placeholder="Global default"
          value={form.sla_high_days ?? ''}
          onChange={e => { if (e.target.value === '') { set('sla_high_days', null); return } const n = Number(e.target.value); set('sla_high_days', Number.isFinite(n) && Number.isInteger(n) && n >= 1 ? n : null) }}
        />
        <Input
          label="SLA: Medium (days)"
          type="number"
          min={1}
          placeholder="Global default"
          value={form.sla_medium_days ?? ''}
          onChange={e => { if (e.target.value === '') { set('sla_medium_days', null); return } const n = Number(e.target.value); set('sla_medium_days', Number.isFinite(n) && Number.isInteger(n) && n >= 1 ? n : null) }}
        />
        {scanOptions ? (
          <div className="edit-form-span2">
            <ScanArgsField
              key={`${scan.id}-${scanOptionsVersion}`}
              options={scanOptions}
              defaultScanFlags={form.scan_flags}
              onChange={v => set('scan_flags', v)}
            />
          </div>
        ) : (
          <div className="edit-form-span2 scan-unavailable-text">
            Scan options unavailable — save without changes or reload to edit scan flags.
          </div>
        )}
        <Select label="Credential" value={String(form.credential_id)} onChange={e => set('credential_id', e.target.value)}>
          <option value="">— none —</option>
          {credentials.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select label="Config template" value={String(form.config_template_id)} onChange={e => set('config_template_id', e.target.value)}>
          <option value="">— none —</option>
          {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </Select>
        <Select label="Min notify severity" value={form.min_notify_severity} onChange={e => set('min_notify_severity', e.target.value)}>
          {SEV_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Input label="Notify recipients (comma-separated)" value={form.notify_recipients} onChange={e => set('notify_recipients', e.target.value)} />
      </div>
      <div className="edit-form-footer">
        <label className="edit-form-enabled-label">
          <input type="checkbox" checked={form.is_enabled} onChange={e => set('is_enabled', e.target.checked)} />
          Enabled
        </label>
        <Button variant="primary" onClick={submit}>Save</Button>
      </div>
      {confirmOpen && pendingPatch && (
        <Modal title="Scan configuration changed" onClose={() => { setConfirmOpen(false); setPendingPatch(null) }}>
          <p className="text-sm text-muted-foreground mb-5">
            Changing scan options, subfolder, or config template will close all open findings for this scan on the next run, because the results are no longer comparable.
          </p>
          <div className="flex gap-2 justify-end">
            <Button variant="secondary" onClick={() => { setConfirmOpen(false); setPendingPatch(null) }}>Cancel</Button>
            <Button onClick={() => { setConfirmOpen(false); onSave(pendingPatch); setPendingPatch(null) }}>Save anyway</Button>
          </div>
        </Modal>
      )}
    </div>
  )
}

function AddModal({
  credentials, templates, defaultTz, scanOptions, scanOptionsVersion, onClose, onCreate,
}: {
  credentials: RepoCredential[]
  templates: ConfigTemplate[]
  defaultTz: string | null
  scanOptions: ScanOptions | null
  scanOptionsVersion: number
  onClose: () => void
  onCreate: (data: Parameters<typeof api.repoScans.create>[0]) => void
}) {
  const [form, setForm] = useState({
    name: '', url: '', branch: 'main', cron_schedule: '', cron_timezone: '',
    credential_id: '', config_template_id: '', pa_version: '', scan_flags: '', subfolder: '',
    min_notify_severity: 'medium' as AlertSeverity,
    notify_recipients: '', is_enabled: true,
  })
  const set = (k: string, v: unknown) => setForm(prev => ({ ...prev, [k]: v }))

  const submit = () => {
    if (!form.name || !form.url) return
    onCreate({
      name: form.name, url: form.url, branch: form.branch,
      cron_schedule: form.cron_schedule || null,
      cron_timezone: form.cron_timezone || null,
      credential_id: form.credential_id ? Number(form.credential_id) : null,
      config_template_id: form.config_template_id ? Number(form.config_template_id) : null,
      pa_version: form.pa_version || null,
      scan_flags: form.scan_flags || null,
      subfolder: form.subfolder || null,
      min_notify_severity: form.min_notify_severity,
      notify_recipients: form.notify_recipients.split(',').map(s => s.trim()).filter(Boolean),
      is_enabled: form.is_enabled,
    })
  }

  return (
    <Modal title="Add repo scan" onClose={onClose}>
      <div className="add-modal-form">
        <Input label="Name" value={form.name} onChange={e => set('name', e.target.value)} />
        <Input label="URL" placeholder="https://github.com/org/repo" value={form.url} onChange={e => set('url', e.target.value)} />
        <Input label="Branch" value={form.branch} onChange={e => set('branch', e.target.value)} />
        <CronField value={form.cron_schedule} onChange={v => set('cron_schedule', v)} placeholder="0 * * * * (leave blank for manual only)" timezone={form.cron_timezone || defaultTz} />
        <TimezoneField value={form.cron_timezone} onChange={v => set('cron_timezone', v)} placeholder={`default: ${defaultTz ?? 'UTC'}`} />
        <Input label="PA version" placeholder="latest from PyPI" value={form.pa_version} onChange={e => set('pa_version', e.target.value)} />
        <Input label="Subfolder" placeholder="e.g. backend (leave blank to scan repo root)" value={form.subfolder} onChange={e => set('subfolder', e.target.value)} />
        {scanOptions ? (
          <ScanArgsField
            key={scanOptionsVersion}
            options={scanOptions}
            defaultScanFlags={form.scan_flags}
            onChange={v => set('scan_flags', v)}
          />
        ) : (
          <div className="scan-unavailable-text">
            Scan options unavailable — save without changes or reload to edit scan flags.
          </div>
        )}
        <Select label="Credential" value={form.credential_id} onChange={e => set('credential_id', e.target.value)}>
          <option value="">— none —</option>
          {credentials.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <Select label="Config template (optional)" value={form.config_template_id} onChange={e => set('config_template_id', e.target.value)}>
          <option value="">— none —</option>
          {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </Select>
        <Select label="Min notify severity" value={form.min_notify_severity} onChange={e => set('min_notify_severity', e.target.value)}>
          {SEV_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Input label="Notify recipients (comma-separated)" value={form.notify_recipients} onChange={e => set('notify_recipients', e.target.value)} />
        <label className="add-modal-enabled-label">
          <input type="checkbox" checked={form.is_enabled} onChange={e => set('is_enabled', e.target.checked)} />
          Enable immediately
        </label>
        <div className="add-modal-actions">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit}>Create</Button>
        </div>
      </div>
    </Modal>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

type Tab = 'scans' | 'credentials'

export default function RepoScans() {
  const [scans, setScans] = useState<RepoScan[]>([])
  const [credentials, setCredentials] = useState<RepoCredential[]>([])
  const [templates, setTemplates] = useState<ConfigTemplate[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [showAddCredential, setShowAddCredential] = useState(false)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('scans')
  const TAB_IDS: readonly Tab[] = ['scans', 'credentials']
  const { tabRef, onKeyDown: onTabKeyDown } = useRovingTabs(TAB_IDS, tab, setTab)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isOperator = user?.role === 'admin' || user?.role === 'operator'
  const isAdmin = user?.role === 'admin'

  const [defaultTz, setDefaultTz] = useState<string | null>(null)
  const [scanOptions, setScanOptions] = useState<ScanOptions | null>(null)
  const [scanOptionsVersion, setScanOptionsVersion] = useState(0)

  useEffect(() => {
    let mounted = true
    api.repoScans.scanOptions()
      .then(opts => { if (mounted) { setScanOptions(opts); setScanOptionsVersion(v => v + 1) } })
      .catch(e => {
        if (!mounted) return
        console.error('Failed to load scan options:', e)
      })
    return () => { mounted = false }
  }, [])

  const load = useCallback(() =>
    Promise.all([api.repoScans.list(), api.repoCredentials.list(), api.configs.list(), api.systemSettings.list()])
      .then(([s, c, t, settings]) => {
        setScans(s); setCredentials(c); setTemplates(t)
        setDefaultTz(settings.find(x => x.key === 'default_cron_timezone')?.value ?? null)
      })
      .catch(e => show(e.message, 'err'))
      .finally(() => setLoading(false))
  , [show])
  useEffect(() => { load() }, [load])

  const handleAddCredential = async (data: Parameters<typeof api.repoCredentials.create>[0]) => {
    try { await api.repoCredentials.create(data); show('Credential added'); setShowAddCredential(false); load() }
    catch (e: any) { show(e.message, 'err') }
  }

  const handleEditCredential = async (id: number, data: Parameters<typeof api.repoCredentials.update>[1]) => {
    try { await api.repoCredentials.update(id, data); show('Credential updated'); load() }
    catch (e: any) { show(e.message, 'err') }
  }

  const handleDeleteCredential = async (cred: RepoCredential) => {
    if (!confirm(`Delete credential "${cred.name}"?`)) return
    try { await api.repoCredentials.delete(cred.id); show('Credential deleted'); load() }
    catch (e: any) { show(e.message, 'err') }
  }

  const handleCreate = async (data: Parameters<typeof api.repoScans.create>[0]) => {
    try { await api.repoScans.create(data); show('Scan added'); setShowAdd(false); load() }
    catch (e: any) { show(e.message, 'err') }
  }

  const handleUpdate = async (id: number, patch: Partial<RepoScan>) => {
    try { await api.repoScans.update(id, patch); show('Saved'); load() }
    catch (e: any) { show(e.message, 'err') }
  }

  const handleDelete = async (scan: RepoScan) => {
    if (!confirm(`Delete scan "${scan.name}"?`)) return
    try { await api.repoScans.delete(scan.id); show('Deleted'); load() }
    catch (e: any) { show(e.message, 'err') }
  }

  const handleTrigger = async (scan: RepoScan): Promise<void> => {
    try { await api.repoScans.trigger(scan.id); show(`Triggered scan for ${scan.name}`); load() }
    catch (e: any) { show(e.message, 'err'); throw e }
  }

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'scans',       label: 'Repo scans',  count: scans.length },
    { id: 'credentials', label: 'Credentials', count: credentials.length },
  ]

  return (
    <Shell>
      <PageHeader
        title="Repo Scans"
        subtitle="Scheduled and manual repository vulnerability scans"
        action={isOperator ? (
          tab === 'scans'
            ? <Button variant="primary" onClick={() => setShowAdd(true)}><Plus size={13} />Add scan</Button>
            : <Button variant="secondary" onClick={() => setShowAddCredential(true)}><Plus size={13} />Add credential</Button>
        ) : undefined}
      />

      {/* Tab bar */}
      <div className="tab-bar" role="tablist">
        {tabs.map(t => {
          const isActive = tab === t.id
          return (
            <button
              key={t.id}
              ref={tabRef(t.id)}
              type="button"
              role="tab"
              aria-selected={isActive}
              aria-controls={`repo-scans-panel-${t.id}`}
              id={`repo-scans-tab-${t.id}`}
              tabIndex={isActive ? 0 : -1}
              onClick={() => setTab(t.id)}
              onKeyDown={onTabKeyDown}
              className={isActive ? 'tab-btn active' : 'tab-btn'}
            >
              {t.label}
              {!loading && (
                <span className={isActive ? 'tab-count active' : 'tab-count'}>
                  {t.count}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {Toast}
      {showAdd && (
        <AddModal credentials={credentials} templates={templates} defaultTz={defaultTz} scanOptions={scanOptions} scanOptionsVersion={scanOptionsVersion} onClose={() => setShowAdd(false)} onCreate={handleCreate} />
      )}
      {showAddCredential && (
        <Modal title="Add credential" onClose={() => setShowAddCredential(false)}>
          <CredentialForm
            onSave={handleAddCredential}
            onCancel={() => setShowAddCredential(false)}
          />
        </Modal>
      )}

      <section
        id="repo-scans-panel-scans"
        role="tabpanel"
        aria-labelledby="repo-scans-tab-scans"
        hidden={tab !== 'scans'}
        className="repo-scans-content"
      >
        {loading ? (
          <div className="loading-text">Loading…</div>
        ) : scans.length === 0 ? (
          <Empty message="No repo scans configured. Add one to get started." />
        ) : (
          scans.map(scan => (
            <ScanCard
              key={scan.id}
              scan={scan}
              credentials={credentials}
              templates={templates}
              defaultTz={defaultTz}
              scanOptions={scanOptions}
              scanOptionsVersion={scanOptionsVersion}
              isOperator={isOperator}
              isAdmin={isAdmin}
              onUpdate={handleUpdate}
              onDelete={handleDelete}
              onTrigger={handleTrigger}
              show={show}
            />
          ))
        )}
      </section>
      <section
        id="repo-scans-panel-credentials"
        role="tabpanel"
        aria-labelledby="repo-scans-tab-credentials"
        hidden={tab !== 'credentials'}
        className="repo-scans-content"
      >
        <CredentialsPanel
          credentials={credentials}
          isOperator={isOperator}
          isAdmin={isAdmin}
          onEdit={handleEditCredential}
          onDelete={handleDeleteCredential}
        />
      </section>
    </Shell>
  )
}
