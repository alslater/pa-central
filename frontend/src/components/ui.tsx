import { ReactNode, useState, useEffect, forwardRef } from 'react'
import { AlertSeverity, DaemonStatus, ScanStatus } from '@/lib/api'

// ── Badge ─────────────────────────────────────────────────────────────────────

const SEV_CLASSES: Record<AlertSeverity, string> = {
  critical: 'bg-status-fail/15 text-status-fail-text border border-status-fail/30',
  high:     'bg-status-fail/10 text-status-fail-text/85 border border-status-fail/22',
  medium:   'bg-status-review/12 text-status-review-text border border-status-review/30',
  warning:  'bg-status-review/10 text-status-review-text/85 border border-status-review/22',
  low:      'bg-status-info/10 text-status-info-text border border-status-info/25',
  info:     'bg-muted-foreground/10 text-muted-foreground border border-muted-foreground/20',
}

export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-style-tag whitespace-nowrap ${SEV_CLASSES[severity]}`}>
      {severity}
    </span>
  )
}

export function StatusDot({ status }: { status: DaemonStatus }) {
  const colorClass: Record<DaemonStatus, string> = {
    running: 'text-status-pass',
    stopped: 'text-status-fail',
    unknown: 'text-muted-foreground',
  }
  const dotClass: Record<DaemonStatus, string> = {
    running: 'bg-status-pass shadow-[0_0_6px_hsl(var(--status-pass))]',
    stopped: 'bg-status-fail',
    unknown: 'bg-muted-foreground',
  }
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${colorClass[status]}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dotClass[status]}`} />
      {status}
    </span>
  )
}

export function ScanBadge({ status }: { status: ScanStatus }) {
  const classes: Record<ScanStatus, string> = {
    clean:    'bg-status-pass/12 text-status-pass-text',
    findings: 'bg-status-review/12 text-status-review-text',
    error:    'bg-status-fail/12 text-status-fail-text',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-style-tag ${classes[status]}`}>
      {status}
    </span>
  )
}

// ── Card ──────────────────────────────────────────────────────────────────────

export function Card({ children, className, style }: { children: ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`bg-card border border-border rounded-[var(--radius-lg)] shadow-sm ${className ?? ''}`} style={style}>
      {children}
    </div>
  )
}

// ── Button ────────────────────────────────────────────────────────────────────

type BtnVariant = 'primary' | 'secondary' | 'danger' | 'ghost'

const BTN_VARIANT_CLASSES: Record<BtnVariant, string> = {
  primary:   'bg-primary text-primary-foreground border-primary hover:bg-primary/90',
  secondary: 'bg-muted text-foreground border-border hover:bg-muted/70',
  danger:    'bg-status-fail/12 text-status-fail-text border-status-fail/30 hover:bg-status-fail/20',
  ghost:     'bg-transparent text-muted-foreground border-transparent hover:bg-foreground/5',
}

export function Button({
  children, onClick, variant = 'secondary', disabled, type = 'button', className, style, title,
}: {
  children: ReactNode; onClick?: () => void
  variant?: BtnVariant; disabled?: boolean
  type?: 'button' | 'submit'; className?: string; style?: React.CSSProperties; title?: string
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`inline-flex items-center gap-1.5 px-3.5 h-9 rounded-[var(--radius-sm)] text-[13px] font-medium border transition-[background,opacity] duration-150 ${BTN_VARIANT_CLASSES[variant]} ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'} ${className ?? ''}`}
      style={style}
    >
      {children}
    </button>
  )
}

// ── Input ─────────────────────────────────────────────────────────────────────

const inputClass = 'bg-muted border border-border rounded-[var(--radius-sm)] text-foreground px-3 h-9 text-[13px] outline-none w-full'

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement> & { label?: string }>(
  function Input({ label, className, ...props }, ref) {
    return (
      <label className="flex flex-col gap-1.5">
        {label && <span className="text-xs text-muted-foreground font-medium">{label}</span>}
        <input ref={ref} {...props} className={`${inputClass} ${className ?? ''}`} />
      </label>
    )
  }
)

export function Textarea({ label, className, ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label?: string }) {
  return (
    <label className="flex flex-col gap-1.5">
      {label && <span className="text-xs text-muted-foreground font-medium">{label}</span>}
      <textarea {...props} className={`bg-muted border border-border rounded-[var(--radius-sm)] text-foreground px-3 py-2 text-xs font-mono outline-none resize-y min-h-[200px] leading-relaxed w-full ${className ?? ''}`} />
    </label>
  )
}

export function Select({ label, children, className, ...props }: React.SelectHTMLAttributes<HTMLSelectElement> & { label?: string }) {
  return (
    <label className="flex flex-col gap-1.5">
      {label && <span className="text-xs text-muted-foreground font-medium">{label}</span>}
      <select {...props} className={`bg-muted border border-border rounded-[var(--radius-sm)] text-foreground px-3 h-9 text-[13px] outline-none cursor-pointer w-full ${className ?? ''}`}>
        {children}
      </select>
    </label>
  )
}

// ── Modal ─────────────────────────────────────────────────────────────────────

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])
  return (
    <div
      className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-[var(--z-overlay)] p-5"
      onClick={onClose}
    >
      <div
        className="bg-card border border-border rounded-[var(--radius-lg)] p-6 min-w-[440px] max-w-[640px] w-full max-h-[90vh] overflow-auto shadow-lg"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center mb-5">
          <h2 className="text-[15px] font-semibold">{title}</h2>
          <button onClick={onClose} aria-label="Close" className="bg-transparent border-none text-muted-foreground cursor-pointer text-lg leading-none">×</button>
        </div>
        {children}
      </div>
    </div>
  )
}

// ── Empty state ───────────────────────────────────────────────────────────────

export function Empty({ message }: { message: string }) {
  return (
    <div className="py-12 px-6 text-center text-muted-foreground text-[13px]">
      {message}
    </div>
  )
}

// ── Toast ─────────────────────────────────────────────────────────────────────

export function useToast() {
  const [toast, setToast] = useState<{ msg: string; kind: 'ok' | 'err' } | null>(null)
  const show = (msg: string, kind: 'ok' | 'err' = 'ok') => {
    setToast({ msg, kind })
  }
  useEffect(() => {
    if (!toast) return
    const id = setTimeout(() => setToast(null), 3000)
    return () => clearTimeout(id)
  }, [toast])
  const Toast = toast ? (
    <div className={`fixed bottom-6 right-6 px-4 py-2.5 rounded-[var(--radius-sm)] text-[13px] font-medium shadow-md z-[var(--z-toast)] border ${
      toast.kind === 'ok'
        ? 'bg-status-pass/15 border-status-pass/40 text-status-pass-text'
        : 'bg-status-fail/15 border-status-fail/40 text-status-fail-text'
    }`}>
      {toast.msg}
    </div>
  ) : null
  return { show, Toast }
}

// ── Repo scan status badge ────────────────────────────────────────────────────

export function RepoScanStatusBadge({ status }: { status: string }) {
  const classes: Record<string, string> = {
    pending: 'bg-muted-foreground/12 text-muted-foreground',
    running: 'bg-status-info/12 text-status-info-text',
    success: 'bg-status-pass/12 text-status-pass-text',
    failed:  'bg-status-fail/12 text-status-fail-text',
  }
  const cls = classes[status] ?? classes.pending
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-style-tag ${cls}`}>
      {status}
    </span>
  )
}

// ── Findings table ────────────────────────────────────────────────────────────

interface Finding {
  package?: string
  ecosystem?: string
  version?: string
  advisory_id?: string
  severity?: string
  summary?: string
  details?: string
  fixed_versions?: string[]
  url?: string
  is_malicious?: boolean
  [key: string]: unknown
}

const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, warning: 3, low: 4, info: 5,
}

const PAGE_SIZE = 25

export function FindingsTable({ findings }: { findings: Record<string, unknown>[] }) {
  const [expanded, setExpanded] = useState<number | null>(null)
  const [page, setPage] = useState(0)
  const items = [...findings].sort((a, b) => {
    const f = a as Finding, g = b as Finding
    return (SEV_ORDER[f.severity?.toLowerCase() ?? 'info'] ?? 9) -
           (SEV_ORDER[g.severity?.toLowerCase() ?? 'info'] ?? 9)
  }) as Finding[]

  if (!items.length) return null

  const totalPages = Math.ceil(items.length / PAGE_SIZE)
  const pageItems = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div className="flex flex-col">
      {pageItems.map((f, i) => {
        const globalIndex = page * PAGE_SIZE + i
        const rawSev = f.severity?.toLowerCase() ?? 'info'
        const sev = (rawSev === 'moderate' ? 'medium' : SEV_CLASSES[rawSev as AlertSeverity] ? rawSev : 'info') as AlertSeverity
        const isExp = expanded === globalIndex
        return (
          <div key={globalIndex} className="border-b border-border">
            <div
              onClick={() => setExpanded(isExp ? null : globalIndex)}
              className="flex items-center gap-2.5 px-4 py-2.5 cursor-pointer"
            >
              <SeverityBadge severity={sev} />
              <span className="font-mono text-xs font-semibold">
                {f.package ?? '—'}
              </span>
              {f.version && (
                <span className="text-[11px] text-muted-foreground">{f.version}</span>
              )}
              {f.ecosystem && (
                <span className="text-[11px] text-muted-foreground uppercase">{f.ecosystem}</span>
              )}
              {f.is_malicious && (
                <span className="text-[11px] text-status-fail-text font-semibold">⚠ MALICIOUS</span>
              )}
              <span className="flex-1 text-xs text-muted-foreground overflow-hidden text-ellipsis whitespace-nowrap">
                {f.summary ?? ''}
              </span>
              {f.advisory_id && (
                <span className="text-[11px] text-muted-foreground font-mono shrink-0">{f.advisory_id}</span>
              )}
            </div>
            {isExp && (
              <div className="px-4 pb-3.5 flex flex-col gap-2">
                {f.details && (
                  <p className="text-xs text-muted-foreground m-0 leading-relaxed whitespace-pre-wrap">{f.details}</p>
                )}
                {f.fixed_versions && f.fixed_versions.length > 0 && (
                  <div className="text-xs">
                    <span className="text-muted-foreground">Fixed in: </span>
                    <span className="font-mono text-status-pass-text">{f.fixed_versions.join(', ')}</span>
                  </div>
                )}
                {f.fixed_versions && f.fixed_versions.length === 0 && (
                  <div className="text-xs text-muted-foreground">No fix available</div>
                )}
                {f.url && (
                  <a href={f.url} target="_blank" rel="noreferrer" className="text-xs text-status-info-text">{f.url}</a>
                )}
              </div>
            )}
          </div>
        )
      })}
      {totalPages > 1 && (
        <div className="flex items-center gap-2 px-4 py-2.5 border-t border-border">
          <button
            type="button"
            onClick={() => { setPage(p => p - 1); setExpanded(null) }}
            disabled={page === 0}
            className={`text-xs px-2.5 py-1 rounded border border-border bg-muted ${page === 0 ? 'text-muted-foreground cursor-default' : 'text-foreground cursor-pointer'}`}
          >←</button>
          <span className="text-xs text-muted-foreground">
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, items.length)} of {items.length}
          </span>
          <button
            type="button"
            onClick={() => { setPage(p => p + 1); setExpanded(null) }}
            disabled={page >= totalPages - 1}
            className={`text-xs px-2.5 py-1 rounded border border-border bg-muted ${page >= totalPages - 1 ? 'text-muted-foreground cursor-default' : 'text-foreground cursor-pointer'}`}
          >→</button>
        </div>
      )}
    </div>
  )
}

export function timeAgo(iso: string): string {
  const hasOffset = iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso)
  const diff = Date.now() - new Date(hasOffset ? iso : iso + 'Z').getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function timeUntil(iso: string): string {
  const hasOffset = iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso)
  const diff = new Date(hasOffset ? iso : iso + 'Z').getTime() - Date.now()
  if (diff <= 0) return 'expired'
  const m = Math.max(1, Math.floor(diff / 60000))
  if (m < 60) return `${m}m`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h`
  return `${Math.floor(h / 24)}d`
}
