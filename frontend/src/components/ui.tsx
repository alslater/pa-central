import { ReactNode, useState, useEffect, useRef, useCallback, useMemo, useId, forwardRef } from 'react'
import { api, AlertSeverity, DaemonStatus, FindingRecord, ScanStatus } from '@/lib/api'

// ── URL sanitization ──────────────────────────────────────────────────────────

export function safeUrl(url: string | null | undefined): string | undefined {
  if (!url) return undefined
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : undefined
  } catch {
    return undefined
  }
}

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
      <textarea {...props} className={`bg-muted border border-border rounded-[var(--radius-sm)] text-foreground px-3 py-2 text-xs font-mono outline-none resize-y min-h-[80px] leading-relaxed w-full ${className ?? ''}`} />
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

// ── Shared dialog accessibility hook ─────────────────────────────────────────

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled])',
  'select:not([disabled])', 'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

function useDialogAccessibility(onClose: () => void) {
  const panelRef = useRef<HTMLDivElement>(null)

  // Restore focus to the element that was active when the dialog opened.
  useEffect(() => {
    const trigger = document.activeElement as HTMLElement | null
    return () => {
      if (trigger && document.contains(trigger)) {
        try { trigger.focus() } catch { /* element no longer focusable */ }
      }
    }
  }, [])

  // Move focus into the panel on mount, trap it while open.
  useEffect(() => {
    const panel = panelRef.current
    if (!panel) return

    const focusables = () => Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE))
    // Fall back to the panel itself when it has no focusable descendants.
    const firstFocusable = focusables()[0] ?? panel
    firstFocusable.focus()

    // Capture phase on document: fires before any bubbling handler.
    // panel.contains() scopes Tab to this panel. Escape is also scoped, but
    // additionally fires when focus has escaped to body/document (browser
    // quirk or devtools) — stopImmediatePropagation prevents sibling dialogs
    // registered on the same target+phase from also closing.
    const focusIsHere = () => {
      const a = document.activeElement
      return panel.contains(a) || a === document.body || a === document.documentElement
    }
    const trap = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (!focusIsHere()) return
        e.stopImmediatePropagation()
        onClose()
        return
      }
      if (!focusIsHere() || e.key !== 'Tab') return
      const els = focusables()
      // No focusable children: keep focus on the panel and suppress Tab.
      if (!els.length) { e.preventDefault(); panel.focus(); return }
      const active = document.activeElement
      const first = els[0], last = els[els.length - 1]
      // Focus escaped to body/documentElement: pull it back to the panel edge.
      if (!panel.contains(active)) {
        e.preventDefault()
        ;(e.shiftKey ? last : first).focus()
        return
      }
      if (e.shiftKey) {
        if (active === first || active === panel) { e.preventDefault(); last.focus() }
      } else {
        if (active === last || active === panel) { e.preventDefault(); first.focus() }
      }
    }

    document.addEventListener('keydown', trap, { capture: true })
    return () => document.removeEventListener('keydown', trap, { capture: true })
  }, [onClose])

  return panelRef
}

// ── Modal ─────────────────────────────────────────────────────────────────────

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose // eslint-disable-line react-hooks/refs
  const stableClose = useCallback(() => onCloseRef.current(), [])
  const panelRef = useDialogAccessibility(stableClose)
  const titleId = useId()
  return (
    <div
      className="fixed inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-[var(--z-overlay)] p-5"
      onClick={stableClose}
      role="presentation"
    >
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/click-events-have-key-events -- role="dialog" legitimately captures clicks to prevent backdrop dismissal */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="bg-card border border-border rounded-[var(--radius-lg)] p-6 min-w-[440px] max-w-[640px] w-full max-h-[90vh] overflow-auto shadow-lg outline-none"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center mb-5">
          <h2 id={titleId} className="text-[15px] font-semibold">{title}</h2>
          <button type="button" onClick={stableClose} aria-label="Close" className="bg-transparent border-none text-muted-foreground cursor-pointer text-lg leading-none">×</button>
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

// ── Drawer ────────────────────────────────────────────────────────────────────

export function Drawer({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose // eslint-disable-line react-hooks/refs
  const stableClose = useCallback(() => onCloseRef.current(), [])
  const panelRef = useDialogAccessibility(stableClose)
  const titleId = useId()
  return (
    <div
      className="fixed inset-0 bg-background/60 backdrop-blur-sm z-[var(--z-overlay)]"
      onClick={stableClose}
      role="presentation"
    >
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions, jsx-a11y/click-events-have-key-events -- role="dialog" legitimately captures clicks to prevent backdrop dismissal */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="absolute top-0 right-0 h-full w-[480px] max-w-[95vw] bg-card border-l border-border shadow-xl flex flex-col overflow-hidden outline-none"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center px-5 py-4 border-b border-border shrink-0">
          <h2 id={titleId} className="text-[15px] font-semibold">{title}</h2>
          <button type="button" onClick={stableClose} aria-label="Close" className="bg-transparent border-none text-muted-foreground cursor-pointer text-xl leading-none hover:text-foreground">×</button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {children}
        </div>
      </div>
    </div>
  )
}

// ── Toast ─────────────────────────────────────────────────────────────────────

export function useToast() {
  const [toast, setToast] = useState<{ msg: string; kind: 'ok' | 'err' } | null>(null)
  const show = useCallback((msg: string, kind: 'ok' | 'err' = 'ok') => {
    setToast({ msg, kind })
  }, [])
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

// ── Finding acceptance controls ───────────────────────────────────────────────

export function FindingAcceptForm({
  finding,
  onDone,
  onCancel,
  show,
  size = 'md',
}: {
  finding: FindingRecord
  onDone: () => void
  onCancel: () => void
  show: (msg: string, kind: 'ok' | 'err') => void
  size?: 'sm' | 'md'
}) {
  const [reason, setReason] = useState('')
  const [acceptedUntil, setAcceptedUntil] = useState('')
  const [submitting, setSubmitting] = useState(false)

  // Compute tomorrow in UTC to match the server's date.today() (UTC).
  const tomorrow = (() => {
    const d = new Date()
    d.setUTCDate(d.getUTCDate() + 1)
    return d.toISOString().slice(0, 10)
  })()
  // Both are YYYY-MM-DD strings — lexicographic order is correct for ISO dates
  // and avoids browser inconsistencies in Date() parsing of date-only strings.
  const dateInvalid = !!acceptedUntil && acceptedUntil < tomorrow

  const handleAccept = async () => {
    if (submitting) return
    setSubmitting(true)
    try {
      await api.findings.accept(finding.id, { reason: reason.trim(), accepted_until: acceptedUntil || undefined })
      setReason(''); setAcceptedUntil('')
      show('Finding accepted', 'ok')
      onDone()
    } catch (e: any) {
      show(e.message ?? 'Failed to accept finding', 'err')
    } finally {
      setSubmitting(false)
    }
  }

  const inputCls = size === 'sm' ? 'text-[12px]' : undefined

  return (
    <div className="flex flex-col gap-2">
      <Textarea
        label="Reason (required)"
        value={reason}
        onChange={e => setReason(e.target.value)}
        rows={size === 'sm' ? 2 : 3}
        maxLength={1000}
        className={inputCls}
      />
      <div>
        <Input
          label="Expires (optional)"
          type="date"
          min={tomorrow}
          value={acceptedUntil}
          onChange={e => setAcceptedUntil(e.target.value)}
          className={inputCls}
        />
        {dateInvalid && (
          <p className="mt-1 text-[11px] text-status-fail-text">Expiry must be a future date.</p>
        )}
      </div>
      <div className="flex gap-2">
        <Button
          variant="primary"
          disabled={!reason.trim() || dateInvalid || submitting}
          onClick={handleAccept}
          className={size === 'sm' ? 'text-[11px] px-2.5 h-7' : 'text-[12px] px-3 h-8'}
        >
          {submitting ? 'Saving…' : 'Save'}
        </Button>
        <Button
          variant="ghost"
          disabled={submitting}
          onClick={onCancel}
          className={size === 'sm' ? 'text-[11px] px-2.5 h-7' : 'text-[12px] px-3 h-8'}
        >
          Cancel
        </Button>
      </div>
    </div>
  )
}

export function FindingRevokeButton({
  finding,
  onDone,
  show,
  size = 'md',
}: {
  finding: FindingRecord
  onDone: () => void
  show: (msg: string, kind: 'ok' | 'err') => void
  size?: 'sm' | 'md'
}) {
  const [submitting, setSubmitting] = useState(false)

  const handleRevoke = async () => {
    if (submitting) return
    setSubmitting(true)
    try {
      await api.findings.revokeAccept(finding.id)
      show('Acceptance revoked', 'ok')
      onDone()
    } catch (e: any) {
      show(e.message ?? 'Failed to revoke acceptance', 'err')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Button
      variant="ghost"
      disabled={submitting}
      onClick={handleRevoke}
      className={size === 'sm' ? 'text-[11px] px-2.5 h-7' : 'text-[12px] px-3 h-8'}
    >
      {submitting ? 'Revoking…' : `Revoke${size === 'md' ? ' acceptance' : ''}`}
    </Button>
  )
}

// ── Shared finding detail ─────────────────────────────────────────────────────

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div className="py-2 border-b border-border/50 last:border-0">
      <div className="text-[11px] text-muted-foreground mb-0.5">{label}</div>
      <div className="text-[13px] break-words">{value}</div>
    </div>
  )
}

export function FindingRecordDetail({ f, children }: { f: FindingRecord; children?: ReactNode }) {
  const statusLabel = f.is_accepted ? 'Accepted' : f.in_breach ? 'Breaching SLA' : 'Open'
  const statusClass = f.is_accepted
    ? 'bg-status-info/12 text-status-info-text'
    : f.in_breach
    ? 'bg-status-fail/12 text-status-fail-text'
    : 'bg-muted text-muted-foreground'

  return (
    <div className="flex flex-col gap-0">
      <div className="flex flex-wrap gap-2 mb-4">
        <SeverityBadge severity={f.severity} />
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-style-tag ${statusClass}`}>{statusLabel}</span>
        {f.is_malicious && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-fail/12 text-status-fail-text">⚠ Malicious</span>
        )}
        {f.reopen_count > 0 && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-muted text-muted-foreground">Reopened ×{f.reopen_count}</span>
        )}
      </div>

      <DetailRow label="Package" value={<span className="font-mono font-medium">{f.package}{f.package_version ? ` ${f.package_version}` : ''}</span>} />
      <DetailRow label="Ecosystem" value={f.ecosystem} />
      <DetailRow label="Advisory ID" value={<span className="font-mono">{f.advisory_id}</span>} />
      {f.scan_name && <DetailRow label="Repo" value={f.scan_name} />}
      <DetailRow label="Open since" value={`${f.days_open} day${f.days_open !== 1 ? 's' : ''}${f.sla_days ? ` (SLA: ${f.sla_days}d)` : ''}`} />

      {f.summary && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Summary</div>
          <div className="text-[13px] leading-relaxed">{f.summary}</div>
        </div>
      )}
      <DetailRow label="Fixed versions" value={f.fixed_versions
        ? <span className="font-mono text-status-pass-text">{f.fixed_versions}</span>
        : <span className="text-muted-foreground">No fix available</span>}
      />
      {(() => { const href = safeUrl(f.url); return href && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Reference</div>
          <a href={href} target="_blank" rel="noopener noreferrer" className="text-[13px] text-status-info-text break-all">{f.url}</a>
        </div>
      )})()}
      {f.details && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Details</div>
          <div className="text-[12px] text-muted-foreground leading-relaxed whitespace-pre-wrap">{f.details}</div>
        </div>
      )}

      {f.is_accepted && (
        <div className="mt-3 p-3 rounded bg-status-info/8 border border-status-info/20">
          <div className="text-[11px] text-muted-foreground mb-1">Accepted</div>
          {f.accepted_reason && <div className="text-[13px] mb-1">{f.accepted_reason}</div>}
          {f.accepted_until && <div className="text-[11px] text-muted-foreground">Expires: {f.accepted_until}</div>}
        </div>
      )}

      {children}
    </div>
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
  fixed_versions?: string | string[] | null
  url?: string
  is_malicious?: boolean
  [key: string]: unknown
}

const SEV_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, warning: 3, low: 4, info: 5,
}

const PAGE_SIZE = 25

function RawFindingDetail({ f }: { f: Finding }) {
  const rawSev = f.severity?.toLowerCase() ?? 'info'
  const sev = (rawSev === 'moderate' ? 'medium' : SEV_CLASSES[rawSev as AlertSeverity] ? rawSev : 'info') as AlertSeverity
  const fixedStr = Array.isArray(f.fixed_versions)
    ? f.fixed_versions.join(', ')
    : typeof f.fixed_versions === 'string' ? f.fixed_versions : null
  return (
    <div className="flex flex-col gap-0">
      <div className="flex flex-wrap gap-2 mb-4">
        <SeverityBadge severity={sev} />
        {f.is_malicious && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-style-tag bg-status-fail/12 text-status-fail-text">⚠ Malicious</span>
        )}
      </div>
      {f.package && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Package</div>
          <div className="text-[13px] font-mono font-medium">{f.package}{f.version ? ` ${f.version}` : ''}</div>
        </div>
      )}
      {f.ecosystem && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Ecosystem</div>
          <div className="text-[13px]">{f.ecosystem}</div>
        </div>
      )}
      {f.advisory_id && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Advisory ID</div>
          <div className="text-[13px] font-mono">{f.advisory_id}</div>
        </div>
      )}
      {f.summary && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Summary</div>
          <div className="text-[13px] leading-relaxed">{f.summary}</div>
        </div>
      )}
      <div className="py-2 border-b border-border/50">
        <div className="text-[11px] text-muted-foreground mb-0.5">Fixed versions</div>
        {fixedStr
          ? <div className="text-[13px] font-mono text-status-pass-text">{fixedStr}</div>
          : <div className="text-[13px] text-muted-foreground">No fix available</div>
        }
      </div>
      {(() => { const href = safeUrl(typeof f.url === 'string' ? f.url : undefined); return href && (
        <div className="py-2 border-b border-border/50">
          <div className="text-[11px] text-muted-foreground mb-0.5">Reference</div>
          <a href={href} target="_blank" rel="noopener noreferrer" className="text-[13px] text-status-info-text break-all">{href}</a>
        </div>
      )})()}
      {f.details && (
        <div className="py-2">
          <div className="text-[11px] text-muted-foreground mb-0.5">Details</div>
          <div className="text-[12px] text-muted-foreground leading-relaxed whitespace-pre-wrap">{f.details}</div>
        </div>
      )}
      {f.closed_reason === 'config_change' && (
        <div className="py-2 border-t border-border/50 mt-2">
          <div className="text-[12px] text-muted-foreground">Closed because scan configuration changed</div>
        </div>
      )}
    </div>
  )
}

export function FindingsTable({ findings }: { findings: Record<string, unknown>[] }) {
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [page, setPage] = useState(0)

  const { items, rowKeys, rowKeyIndex } = useMemo(() => {
    const sorted = [...findings].sort((a, b) => {
      const f = a as Finding, g = b as Finding
      return (SEV_ORDER[f.severity?.toLowerCase() ?? 'info'] ?? 9) -
             (SEV_ORDER[g.severity?.toLowerCase() ?? 'info'] ?? 9)
    }) as Finding[]
    // Build stable row keys: identity tuple is preferred; append a
    // disambiguating counter only for rows that share the same triple.
    const keyCounts = new Map<string, number>()
    const keys = sorted.map(f => {
      // JSON.stringify the tuple so field values containing the delimiter
      // can't produce collisions.
      const base = JSON.stringify([f.advisory_id ?? '', f.package ?? '', f.ecosystem ?? ''])
      const n = (keyCounts.get(base) ?? 0) + 1
      keyCounts.set(base, n)
      return n > 1 ? `${base}:${n}` : base
    })
    const index = new Map(keys.map((k, i) => [k, i]))
    return { items: sorted, rowKeys: keys, rowKeyIndex: index }
  }, [findings])

  // Resolve the selected item by its stable rowKey so selection survives
  // findings updates (new results, reordering, insertions, removals).
  const selectedIdx = selectedKey !== null ? (rowKeyIndex.get(selectedKey) ?? -1) : -1
  const selected = selectedIdx !== -1 ? items[selectedIdx] : null

  if (!items.length) return null

  const totalPages = Math.ceil(items.length / PAGE_SIZE)
  const pageItems = items.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <>
    <div className="flex flex-col">
      {pageItems.map((f, i) => {
        const itemIndex = page * PAGE_SIZE + i
        const rowKey = rowKeys[itemIndex]
        const rawSev = f.severity?.toLowerCase() ?? 'info'
        const sev = (rawSev === 'moderate' ? 'medium' : SEV_CLASSES[rawSev as AlertSeverity] ? rawSev : 'info') as AlertSeverity
        return (
          <div key={rowKey} className="border-b border-border">
            <div
              onClick={() => setSelectedKey(k => k === rowKey ? null : rowKey)}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedKey(k => k === rowKey ? null : rowKey) } }}
              className="flex items-center gap-2.5 px-4 py-2.5 cursor-pointer hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand"
              tabIndex={0}
              role="button"
              aria-label={`${f.package ?? 'finding'} — view details`}
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
          </div>
        )
      })}
      {totalPages > 1 && (
        <div className="flex items-center gap-2 px-4 py-2.5 border-t border-border">
          <button
            type="button"
            onClick={() => { setPage(p => p - 1); setSelectedKey(null) }}
            disabled={page === 0}
            className={`text-xs px-2.5 py-1 rounded border border-border bg-muted ${page === 0 ? 'text-muted-foreground cursor-default' : 'text-foreground cursor-pointer'}`}
          >←</button>
          <span className="text-xs text-muted-foreground">
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, items.length)} of {items.length}
          </span>
          <button
            type="button"
            onClick={() => { setPage(p => p + 1); setSelectedKey(null) }}
            disabled={page >= totalPages - 1}
            className={`text-xs px-2.5 py-1 rounded border border-border bg-muted ${page >= totalPages - 1 ? 'text-muted-foreground cursor-default' : 'text-foreground cursor-pointer'}`}
          >→</button>
        </div>
      )}
    </div>
    {selected && (
      <Drawer
        title={`${selected.package ?? '—'} — ${selected.advisory_id ?? 'Finding'}`}
        onClose={() => setSelectedKey(null)}
      >
        <RawFindingDetail f={selected} />
      </Drawer>
    )}
    </>
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
