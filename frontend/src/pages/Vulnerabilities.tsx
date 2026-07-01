import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { api, FindingRecord, FindingSettings, AlertSeverity } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Button, Card, Drawer, Empty, FindingAcceptForm, FindingRecordDetail, FindingRevokeButton, Input, Select, SeverityBadge, useToast } from '@/components/ui'
import { useLocalStorage } from '@/lib/hooks'
import { Settings2 } from 'lucide-react'

const SEVERITIES: AlertSeverity[] = ['critical', 'high', 'medium', 'warning', 'low', 'info']

type BreachFilter = 'all' | 'breaching' | 'accepted'
type SortKey = 'severity' | 'days_open' | 'repo'

const SEVERITY_ORDER = {
  critical: 0, high: 1, medium: 2, warning: 3, low: 4, info: 5,
} as const satisfies Record<AlertSeverity, number>

const PAGE_SIZE = 50

function FindingDetailPanel({ finding: f }: { finding: FindingRecord }) {
  return <FindingRecordDetail f={f} />
}

export default function Vulnerabilities() {
  const [findings, setFindings] = useState<FindingRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [severityFilter, setSeverityFilter] = useLocalStorage<AlertSeverity[]>('vuln-severity-filter', [])
  const [breachFilter, setBreachFilter] = useLocalStorage<BreachFilter>('vuln-breach-filter', 'all')
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [page, setPage] = useState(0)
  const [settings, setSettings] = useState<FindingSettings | null>(null)
  const [settingsError, setSettingsError] = useState<string | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  type SettingsForm = { [K in keyof FindingSettings]: number | '' }
  const [settingsForm, setSettingsForm] = useState<SettingsForm>({ sla_high_days: 14, sla_medium_days: 90, finding_retention_days: 365 })
  const [acceptingId, setAcceptingId] = useState<number | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<FindingRecord | null>(null)
  const { show, Toast } = useToast()

  const reqSeq = React.useRef(0)
  const settingsSeq = React.useRef(0)

  const load = useCallback(async (background = false) => {
    const seq = ++reqSeq.current
    if (background) setRefreshing(true)
    else setLoading(true)
    try {
      const data = await api.findings.listAll({
        limit: 500,
        severity: severityFilter.length ? severityFilter : undefined,
        breach: breachFilter === 'breaching' ? true : undefined,
        accepted: breachFilter === 'accepted' ? true : undefined,
      })
      if (seq !== reqSeq.current) return
      setFindings(data)
      setSelectedFinding(prev => prev ? (data.find(f => f.id === prev.id) ?? null) : null)
    } catch (e: any) {
      if (seq !== reqSeq.current) return
      show(e.message ?? 'Failed to load findings', 'err')
    } finally {
      if (seq === reqSeq.current) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [severityFilter, breachFilter, show])

  const loadSettings = useCallback(() => {
    const seq = ++settingsSeq.current
    api.findingSettings.get()
      .then(s => {
        if (seq !== settingsSeq.current) return
        setSettings(s); setSettingsForm(s); setSettingsError(null)
      })
      .catch((e: any) => {
        if (seq !== settingsSeq.current) return
        setSettingsError(e.message ?? 'Failed to load settings')
        show(e.message ?? 'Failed to load settings', 'err')
      })
  }, [show])

  useEffect(() => { load(); return () => { reqSeq.current++ } }, [load])
  useEffect(() => { loadSettings(); return () => { settingsSeq.current++ } }, [loadSettings])

  const sorted = useMemo(() => [...findings].sort((a, b) => {
    if (sortKey === 'severity') return (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    if (sortKey === 'days_open') return b.days_open - a.days_open
    if (sortKey === 'repo') return (a.scan_name ?? '').localeCompare(b.scan_name ?? '')
    return 0
  }), [findings, sortKey])

  const totalPages = Math.ceil(sorted.length / PAGE_SIZE)
  useEffect(() => {
    if (totalPages > 0) setPage(p => Math.min(p, totalPages - 1))
  }, [totalPages])
  useEffect(() => { setAcceptingId(null) }, [severityFilter, breachFilter, sortKey])
  const paged = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  const settingsFormValid = (Object.values(settingsForm) as (number | '')[]).every(
    v => v !== '' && Number.isInteger(v) && v >= 1
  )

  const updateSettingsField = (key: keyof FindingSettings, raw: string) => {
    if (raw === '') { setSettingsForm(f => ({ ...f, [key]: '' })); return }
    const n = Number(raw)
    setSettingsForm(f => ({ ...f, [key]: Number.isFinite(n) && Number.isInteger(n) ? n : '' }))
  }

  const saveSettings = async () => {
    if (!settingsFormValid) return
    const payload: FindingSettings = {
      sla_high_days: settingsForm.sla_high_days as number,
      sla_medium_days: settingsForm.sla_medium_days as number,
      finding_retention_days: settingsForm.finding_retention_days as number,
    }
    try {
      const saved = await api.findingSettings.update(payload)
      setSettings(saved)
      setSettingsOpen(false)
      show('Settings saved')
    } catch (e: any) {
      show(e.message ?? 'Failed to save settings', 'err')
    }
  }

  return (
    <Shell>
      <PageHeader
        title="Vulnerabilities"
        subtitle="Open findings across all repo scans"
        action={
          <Button variant="secondary" onClick={() => { if (!settingsOpen && settings) setSettingsForm(settings); setSettingsOpen(o => !o) }}>
            <Settings2 size={13} /> Settings
          </Button>
        }
      />
      <div className="p-6 px-7 overflow-auto">

        {/* SLA / retention settings panel */}
        {settingsOpen && settingsError && (
          <Card className="mb-4 p-4 flex items-center gap-3 text-[13px] text-status-fail-text">
            <span>Failed to load settings: {settingsError}</span>
            <Button variant="ghost" onClick={loadSettings} className="text-[12px] h-7 px-2.5">Retry</Button>
          </Card>
        )}
        {settingsOpen && !settingsError && !settings && (
          <Card className="mb-4 p-4 text-[13px] text-muted-foreground">Loading settings…</Card>
        )}
        {settingsOpen && !settingsError && settings && (
          <Card className="mb-4 p-4 flex flex-wrap gap-4 items-end">
            {([
              ['sla_high_days', 'SLA: High/Critical (days)'],
              ['sla_medium_days', 'SLA: Medium (days)'],
              ['finding_retention_days', 'Retention (days)'],
            ] as [keyof FindingSettings, string][]).map(([key, label]) => (
              <div key={key} className="w-44">
                <Input
                  label={label}
                  type="number"
                  min={1}
                  step={1}
                  value={settingsForm[key]}
                  onChange={e => updateSettingsField(key, e.target.value)}
                />
              </div>
            ))}
            <div className="flex gap-2">
              <Button variant="primary" onClick={saveSettings} disabled={!settingsFormValid}>Save</Button>
              <Button variant="ghost" onClick={() => { if (settings) setSettingsForm(settings); setSettingsOpen(false) }}>Cancel</Button>
            </div>
          </Card>
        )}

        {/* Filter bar */}
        <div className="flex flex-wrap gap-2.5 mb-4 items-center">
          <div className="flex gap-1">
            {SEVERITIES.map(s => (
              <button
                key={s}
                type="button"
                aria-pressed={severityFilter.includes(s) ? true : false}
                onClick={() => { setSeverityFilter(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]); setPage(0) }}
                className={`px-2 py-0.5 rounded text-style-tag border transition-colors ${
                  severityFilter.includes(s)
                    ? 'bg-foreground text-background border-foreground'
                    : 'bg-muted text-muted-foreground border-border hover:border-foreground/40'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <Select
            value={breachFilter}
            onChange={e => { setBreachFilter(e.target.value as BreachFilter); setPage(0) }}
            className="w-44"
          >
            <option value="all">All findings</option>
            <option value="breaching">Breaching SLA</option>
            <option value="accepted">Accepted</option>
          </Select>
          <Select
            value={sortKey}
            onChange={e => setSortKey(e.target.value as SortKey)}
            className="w-44"
          >
            <option value="severity">Sort: Severity</option>
            <option value="days_open">Sort: Days open</option>
            <option value="repo">Sort: Repo</option>
          </Select>
          <span className="text-[13px] text-muted-foreground ml-auto">
            {sorted.length} findings{refreshing && <span className="ml-1 opacity-50">·</span>}
          </span>
        </div>

        {loading ? (
          <div className="text-muted-foreground text-[13px]">Loading…</div>
        ) : sorted.length === 0 ? (
          <Empty message="No open findings match your filters." />
        ) : (
          <>
            <Card>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-border">
                      {['Repo', 'Severity', 'Package', 'Ecosystem', 'Advisory ID', 'Open since', 'SLA', 'Status', ''].map(h => (
                        <th key={h} className="text-left px-4 py-2.5 text-style-caption">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {paged.map(f => (
                      <React.Fragment key={f.id}>
                        <tr
                          className="border-b border-border/50 hover:bg-muted/40 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand"
                          tabIndex={0}
                          role="button"
                          aria-label={`${f.package} ${f.advisory_id} — view details`}
                          onClick={() => setSelectedFinding(f)}
                          onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedFinding(f) } }}
                        >
                          <td className="px-4 py-2.5 text-[11px] text-muted-foreground whitespace-nowrap">{f.scan_name ?? '—'}</td>
                          <td className="px-4 py-2.5"><SeverityBadge severity={f.severity} /></td>
                          <td className="px-4 py-2.5">
                            <span className="font-mono text-xs font-medium">{f.package}</span>
                            {f.reopen_count > 0 && (
                              <span className="ml-1.5 text-[11px] text-status-review-text" title={`Reopened ${f.reopen_count} time(s)`}>↩×{f.reopen_count}</span>
                            )}
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{f.ecosystem || '—'}</td>
                          <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">{f.advisory_id}</td>
                          <td className={`px-4 py-2.5 text-[11px] font-medium ${f.in_breach ? 'text-status-fail-text' : 'text-muted-foreground'}`}>
                            {f.days_open}d
                          </td>
                          <td className="px-4 py-2.5 text-[11px] text-muted-foreground">{f.sla_days ? `${f.sla_days}d` : '—'}</td>
                          <td className="px-4 py-2.5">
                            {f.is_accepted ? (
                              <span
                                className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-info/12 text-status-info-text"
                                title={`${f.accepted_reason ?? ''}${f.accepted_until ? ` — until ${f.accepted_until}` : ''}`}
                              >
                                Accepted
                              </span>
                            ) : f.in_breach ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-fail/12 text-status-fail-text">
                                Breaching
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-muted text-muted-foreground">
                                Open
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2.5" onClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
                            {f.is_accepted ? (
                              <FindingRevokeButton finding={f} onDone={() => load(true)} show={show} size="sm" />
                            ) : (
                              <Button
                                variant="ghost"
                                onClick={() => setAcceptingId(f.id)}
                                className="text-[11px] px-2.5 h-7"
                              >
                                Accept
                              </Button>
                            )}
                          </td>
                        </tr>
                        {acceptingId === f.id && (
                          <tr className="border-b border-border/50">
                            <td colSpan={9} className="px-4 py-3 bg-muted/40">
                              <FindingAcceptForm
                                finding={f}
                                onDone={() => { setAcceptingId(null); load(true) }}
                                onCancel={() => setAcceptingId(null)}
                                show={show}
                                size="sm"
                              />
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>

            {totalPages > 1 && (
              <div className="flex gap-2 mt-3 justify-end items-center">
                <Button variant="secondary" disabled={page === 0} onClick={() => setPage(p => p - 1)} className="px-2.5 h-8 text-xs">←</Button>
                <span className="text-[13px] text-muted-foreground">Page {page + 1} of {totalPages}</span>
                <Button variant="secondary" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)} className="px-2.5 h-8 text-xs">→</Button>
              </div>
            )}
          </>
        )}
      </div>
      {selectedFinding && (
        <Drawer
          title={`${selectedFinding.package} — ${selectedFinding.advisory_id}`}
          onClose={() => setSelectedFinding(null)}
        >
          <FindingDetailPanel finding={selectedFinding} />
        </Drawer>
      )}
      {Toast}
    </Shell>
  )
}
