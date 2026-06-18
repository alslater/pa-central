import { useMemo } from 'react'
import { CronExpressionParser } from 'cron-parser'
import cronstrue from 'cronstrue'

interface CronResult {
  error: string | null
  description: string | null
  nextRuns: Date[]
}

function parseCron(expr: string, timezone?: string): CronResult {
  if (!expr.trim()) return { error: null, description: null, nextRuns: [] }
  try {
    const description = cronstrue.toString(expr, { throwExceptionOnParseError: true })
    const interval = CronExpressionParser.parse(expr, timezone ? { tz: timezone } : undefined)
    const nextRuns: Date[] = []
    for (let i = 0; i < 10; i++) nextRuns.push(interval.next().toDate())
    return { error: null, description, nextRuns }
  } catch (e: any) {
    return { error: e.message ?? 'Invalid cron expression', description: null, nextRuns: [] }
  }
}

const PRESETS = [
  { label: 'Every hour',    value: '0 * * * *' },
  { label: 'Every 6h',      value: '0 */6 * * *' },
  { label: 'Daily midnight',value: '0 0 * * *' },
  { label: 'Daily 9am',     value: '0 9 * * *' },
  { label: 'Weekly Mon',    value: '0 9 * * 1' },
]

interface Props {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  timezone?: string | null
}

export function CronField({ value, onChange, placeholder = '0 * * * *', timezone }: Props) {
  const tz = timezone || undefined
  const result = useMemo(() => parseCron(value, tz), [value, tz])
  const hasValue = value.trim().length > 0
  const tzLabel = tz ?? 'UTC'

  const fmt = (d: Date) => {
    const opts: Intl.DateTimeFormatOptions = {
      weekday: 'short', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: false,
    }
    try {
      return d.toLocaleString(undefined, tz ? { ...opts, timeZone: tz } : opts)
    } catch {
      return d.toLocaleString(undefined, opts)
    }
  }

  return (
    <fieldset className="flex flex-col gap-1.5 border-none p-0 m-0">
      <legend className="text-xs text-muted-foreground font-medium p-0">Cron schedule</legend>

      {/* Input row */}
      <div className="flex gap-1.5">
        <input
          aria-label="Cron expression"
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          spellCheck={false}
          className={`flex-1 bg-muted border rounded-[var(--radius-sm)] text-foreground px-2.5 py-[7px] text-[13px] font-mono outline-none ${
            result.error && hasValue ? 'border-status-fail/60' : 'border-border'
          }`}
        />
        <select
          aria-label="Cron presets"
          value=""
          onChange={e => { if (e.target.value) onChange(e.target.value) }}
          className="bg-muted border border-border rounded-[var(--radius-sm)] text-muted-foreground px-2 py-[7px] text-xs cursor-pointer outline-none"
        >
          <option value="">Presets…</option>
          {PRESETS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
        </select>
      </div>

      {/* Error */}
      {result.error && hasValue && (
        <div className="text-[11px] text-status-fail-text font-mono">{result.error}</div>
      )}

      {/* Human-readable description */}
      {result.description && (
        <div className="text-xs text-muted-foreground italic">{result.description}</div>
      )}

      {/* Next 10 runs */}
      {result.nextRuns.length > 0 && (
        <div className="bg-muted border border-border rounded-[var(--radius-sm)] overflow-hidden">
          <div className="px-2.5 py-[5px] border-b border-border flex justify-between items-center">
            <span className="text-style-caption">Next 10 executions</span>
            <span className="text-[10px] text-muted-foreground font-mono">{tzLabel}</span>
          </div>
          {result.nextRuns.map((d, i) => (
            <div key={i} className={`flex items-center gap-2.5 px-2.5 py-1 text-xs ${i < 9 ? 'border-b border-border/50' : ''}`}>
              <span className="text-muted-foreground tabular w-4 shrink-0">{i + 1}.</span>
              <span className="font-mono text-foreground">{fmt(d)}</span>
            </div>
          ))}
        </div>
      )}
    </fieldset>
  )
}
