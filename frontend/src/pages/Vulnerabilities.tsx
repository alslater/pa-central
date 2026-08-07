import React, { useCallback, useEffect, useState } from 'react'
import { api, FindingRecord, FindingSettings, AlertSeverity, FindingSortKey, SortDir } from '@/lib/api'
import { Shell, PageHeader } from '@/components/Shell'
import { Button, Card, Drawer, Empty, FindingAcceptForm, FindingRecordDetail, FindingRevokeButton, Input, Select, SeverityBadge, useToast } from '@/components/ui'
import { useLocalStorage } from '@/lib/hooks'
import { Settings2 } from 'lucide-react'

const SEVERITIES: AlertSeverity[] = ['critical', 'high', 'medium', 'warning', 'low', 'info']
const PAGE_SIZE = 50
// Data columns only; the actions column is rendered separately with an sr-only
// label. The expanded detail row spans the whole table, so its colSpan derives
// from this count plus that actions column.
const COLUMNS = ['Repo', 'Severity', 'Package', 'Ecosystem', 'Advisory ID', 'Open since', 'SLA', 'Status'] as const
const COLUMN_COUNT = COLUMNS.length + 1

type BreachFilter = 'all' | 'breaching' | 'accepted'

function FindingDetailPanel({ finding: f }: { finding: FindingRecord }) {
  return <FindingRecordDetail f={f} />
}

export default function Vulnerabilities() {
  const [findings, setFindings] = useState<FindingRecord[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [severityFilter, setSeverityFilter] = useLocalStorage<AlertSeverity[]>('vuln-severity-filter', [])
  const [breachFilter, setBreachFilter] = useLocalStorage<BreachFilter>('vuln-breach-filter', 'all')
  const [sortKey, setSortKey] = useState<FindingSortKey>('severity')
  const sortDir: SortDir = sortKey === 'days_open' ? 'desc' : 'asc'
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
  // Mirrors `page` for callbacks that fire long after their render — the
  // accept/revoke `onDone` handlers run only once an awaited request resolves,
  // by which time the user may have paged away. Reading the ref refreshes
  // whatever page is showing now, rather than refetching the captured page and
  // overwriting the table with rows the pager no longer claims to display.
  // Written in an effect, not during render (a discarded render must not mutate
  // it); declared before the pagination effect so it commits first.
  // Not useEffectEvent: that can only be *called* from effects, and these are
  // event handlers.
  const pageRef = React.useRef(page)
  useEffect(() => { pageRef.current = page }, [page])

  // `page` is passed in rather than closed over, so `load` doesn't rebuild on
  // every page change. Its identity therefore changes only when the filters or
  // sort change, which the pagination effect below relies on.
  const load = useCallback(async (pageArg: number, background = false) => {
    const seq = ++reqSeq.current
    if (background) setRefreshing(true)
    else setLoading(true)
    try {
      const data = await api.findings.list({
        severity: severityFilter.length ? severityFilter : undefined,
        breach: breachFilter === 'breaching' ? true : undefined,
        accepted: breachFilter === 'accepted' ? true : undefined,
        page: pageArg,
        page_size: PAGE_SIZE,
        sort: sortKey,
        sort_dir: sortDir,
      })
      if (seq !== reqSeq.current) return
      setFindings(data.items)
      setTotal(data.total)
      setSelectedFinding(prev => {
        if (!prev) return null
        // Update the selected finding if it's on the current page (picks up
        // any field changes from the refresh). If it's on a different page,
        // preserve the previous value — it still exists, just isn't visible here.
        const refreshed = data.items.find(f => f.id === prev.id)
        return refreshed ?? prev
      })
    } catch (e: any) {
      if (seq !== reqSeq.current) return
      show(e.message ?? 'Failed to load findings', 'err')
    } finally {
      if (seq === reqSeq.current) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [severityFilter, breachFilter, sortKey, sortDir, show])

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

  // Pagination effect: fires when load rebuilds (filter/sort change) or page changes.
  // When load rebuilds and page > 0: reset page to 0 and skip the fetch — the
  // page change re-triggers this effect and the fetch happens then (page 0, one request).
  // When load rebuilds and page is already 0, or when only page changes (navigation):
  // fetch immediately using the current page.
  // The load-identity comparison lives inside the effect: deriving it during
  // render and advancing the ref there would consume the "load changed" signal
  // on a render that may never commit, silently losing the page reset.
  const prevLoadRef = React.useRef(load)
  useEffect(() => {
    const filterReset = prevLoadRef.current !== load
    prevLoadRef.current = load
    if (filterReset) {
      setAcceptingId(null)
      if (page !== 0) {
        // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional: setPage(0) re-triggers this effect which does the fetch
        setPage(0)
        return
      }
    }
    load(page)
    // reqSeq is an abort counter: incrementing in cleanup invalidates in-flight responses so stale data is never committed.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reading reqSeq.current in cleanup is intentional; "stale ref" warning doesn't apply to a counter ref (not a DOM node)
    return () => { reqSeq.current++ }
    // page is included so pagination (prev/next) triggers a fetch.
  }, [load, page])
  useEffect(() => {
    loadSettings()
    // settingsSeq is an abort counter — same pattern as reqSeq above.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- reading settingsSeq.current in cleanup is intentional; "stale ref" warning doesn't apply to a counter ref (not a DOM node)
    return () => { settingsSeq.current++ }
  }, [loadSettings])

  const totalPages = Math.ceil(total / PAGE_SIZE)
  // Clamp page after a background refresh shrinks total (e.g. accept/revoke).
  // Also resets to 0 when the result set empties entirely (totalPages === 0).
  // eslint-disable-next-line react-hooks/set-state-in-effect -- clamps page to valid range when data shrinks; derived-state reset pattern
  useEffect(() => { setPage(p => totalPages > 0 ? Math.min(p, totalPages - 1) : 0) }, [totalPages])

  const paged = findings

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
                onClick={() => setSeverityFilter(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])}
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
            onChange={e => setBreachFilter(e.target.value as BreachFilter)}
            className="w-44"
          >
            <option value="all">All findings</option>
            <option value="breaching">Breaching SLA</option>
            <option value="accepted">Accepted</option>
          </Select>
          <Select
            value={sortKey}
            onChange={e => setSortKey(e.target.value as FindingSortKey)}
            className="w-44"
          >
            <option value="severity">Sort: Severity</option>
            <option value="days_open">Sort: Days open</option>
            <option value="repo">Sort: Repo</option>
          </Select>
          <span className="text-[13px] text-muted-foreground ml-auto">
            {total} findings{refreshing && <span className="ml-1 opacity-50">·</span>}
          </span>
        </div>

        {loading ? (
          <div className="text-muted-foreground text-[13px]">Loading…</div>
        ) : total === 0 ? (
          <Empty message="No open findings match your filters." />
        ) : (
          <>
            <Card>
              <div className="overflow-x-auto">
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
                              <FindingRevokeButton finding={f} onDone={() => load(pageRef.current, true)} show={show} size="sm" />
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
                            <td colSpan={COLUMN_COUNT} className="px-4 py-3 bg-muted/40">
                              <FindingAcceptForm
                                finding={f}
                                onDone={() => { setAcceptingId(null); load(pageRef.current, true) }}
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
