const BASE = '/api'

function getToken() { return localStorage.getItem('token') }

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const token = getToken()
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...opts.headers,
    },
  })
  if (res.status === 401) {
    window.dispatchEvent(new Event('auth:unauthorized'))
    throw new Error('Unauthorized')
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    const detail = Array.isArray(err.detail)
      ? err.detail.map((d: { msg: string }) => d.msg).join(', ')
      : err.detail
    throw new Error(detail || `HTTP ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type UserRole = 'admin' | 'operator' | 'developer' | 'viewer'
export type DaemonStatus = 'running' | 'stopped' | 'unknown'
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'warning' | 'low' | 'info'
export type AlertKind = 'osv' | 'heuristic'
export type ScanStatus = 'clean' | 'findings' | 'error'
export type Ecosystem = 'pypi' | 'npm' | 'packagist' | 'other'

export interface User {
  id: number; email: string; display_name: string
  role: UserRole; is_active: boolean; totp_enabled: boolean; created_at: string
}

export interface TotpChallenge {
  totp_required: true
  totp_setup_required: boolean
  totp_session_token: string
  totp_uri: string | null
}

export interface Host {
  id: number; owner_user_id: number; name: string; description: string | null
  hostname: string | null; tags: string[] | null
  pa_version: string | null; daemon_status: DaemonStatus
  daemon_uptime_seconds: number | null
  last_seen_at: string | null; created_at: string
}

export interface Alert {
  id: number; host_id: number; package_name: string
  package_version: string | null; ecosystem: Ecosystem
  kind: AlertKind; severity: AlertSeverity
  advisory_id: string | null; summary: string | null
  project_path: string | null
  risk_score: number | null; signals: Record<string, unknown>[] | null
  acknowledged: boolean; occurred_at: string; received_at: string
}

export interface Scan {
  id: number; host_id: number; project_path: string
  scan_type: string; status: ScanStatus; finding_count: number
  findings: Record<string, unknown>[] | null
  risks: Record<string, unknown>[] | null
  /** Packages package-alert could not score this scan. Nonzero means an empty/short `risks` list may reflect scoring failure, not a clean scan. */
  risk_failures: number
  sources: string[] | null
  scanned_at: string; received_at: string
}

export interface ConfigTemplate {
  id: number; name: string; description: string | null
  toml_content: string; is_default: boolean; created_by_id: number
  created_at: string; updated_at: string
}

export interface CooldownEntry {
  id: number; package_name: string; package_version: string | null
  ecosystem: Ecosystem; host_id: number | null
  note: string | null; expires_at: string | null
  created_by_id: number; created_at: string
}

export interface ApiKey {
  id: number; name: string; owner_display_name: string
  is_active: boolean; last_used_at: string | null; created_at: string
  raw_key?: string
}

export interface DashboardStats {
  total_hosts: number; hosts_online: number; hosts_offline: number
  unacknowledged_alerts: number; critical_alerts: number
  outstanding_findings_by_severity: Record<AlertSeverity, number> | null
  recent_alerts: Alert[]
}

export interface ExposurePoint {
  date: string
  exposure: number
}

export interface ExposureHistory {
  points: ExposurePoint[]
  window_days: number
}

export type CredentialType = 'none' | 'ssh_key' | 'https_token'
export type RepoScanStatus = 'pending' | 'running' | 'success' | 'failed'
export type ScanTrigger = 'manual' | 'scheduled'
export type SettingValueType = 'string' | 'int' | 'bool' | 'json' | 'secret'

export interface RepoCredential {
  id: number; name: string; credential_type: CredentialType
  created_at: string; updated_at: string
}

export interface RepoScan {
  id: number; name: string; url: string; branch: string
  cron_schedule: string | null; cron_timezone: string | null; is_enabled: boolean
  credential_id: number | null
  config_template_id: number | null; pa_version: string | null; scan_flags: string | null; subfolder: string | null
  sla_high_days: number | null; sla_medium_days: number | null
  min_notify_severity: AlertSeverity; notify_recipients: string[]
  last_scan_at: string | null; created_at: string; updated_at: string; created_by_id: number
  breach: boolean; breach_count: number
  scan_config_hash: string | null
}

export interface RepoScanResult {
  id: number; repo_scan_id: number
  status: RepoScanStatus; triggered_by: ScanTrigger
  pa_version: string | null; finding_count: number | null
  findings: Record<string, unknown>[] | null
  risks: Record<string, unknown>[] | null
  /** Packages package-alert could not score this scan. Nonzero means an
   *  empty/short `risks` list may reflect scoring failure, not a clean scan —
   *  see risk_lifecycle.update_risk_records on the backend for the same rule. */
  risk_failures: number
  sources: string[] | null
  error_message: string | null; ecs_task_arn: string | null
  notified: boolean
  started_at: string | null; completed_at: string | null
}

export interface RepoScanResultWithName extends RepoScanResult {
  scan_name: string; scan_url: string
  /** Current open-breach state for the scan, not the state at the time of this result. */
  scan_breach: boolean; scan_breach_count: number
}

export interface RepoScanHeadline {
  id: number; name: string; url: string
  latest_status: RepoScanStatus | null
  latest_scanned_at: string | null
  open_findings_by_severity: Record<AlertSeverity, number>
  open_risks_by_level: Record<'critical' | 'warning' | 'info', number>
  breach: boolean; breach_count: number
}

export interface FindingRecord {
  id: number
  repo_scan_id: number
  advisory_id: string
  package: string
  ecosystem: string
  severity: AlertSeverity
  first_found_at: string
  closed_at: string | null
  closed_reason: string | null
  reopen_count: number
  accepted_by_id: number | null
  accepted_at: string | null
  accepted_reason: string | null
  accepted_until: string | null
  summary: string | null
  details: string | null
  package_version: string | null
  fixed_versions: string | null
  url: string | null
  is_malicious: boolean | null
  is_accepted: boolean
  days_open: number
  sla_days: number | null
  in_breach: boolean
  scan_name: string | null
}

export type FindingSortKey = 'severity' | 'days_open' | 'repo'
export type SortDir = 'asc' | 'desc'

export interface PaginatedFindings {
  items: FindingRecord[]
  total: number
  page: number
  page_size: number
}

export interface SystemSetting {
  key: string; value: string | null; value_type: SettingValueType
  updated_at: string; updated_by_id: number | null
}

export interface LintResult {
  valid: boolean
  errors: string[]
  warnings: string[]
}

export interface ScanFlag {
  name: string
  cli_flag: string
  help: string
  type: 'bool' | 'str'
}

export interface ScanOptions {
  flags: ScanFlag[]
  exclusions: string[][]
}

export interface RiskSignal {
  name: string
  score: number
  reason: string
}

export interface RiskRecord {
  id: number
  repo_scan_id: number
  package: string
  ecosystem: string
  package_version: string | null
  score: number
  level: 'critical' | 'warning' | 'info'
  signals: RiskSignal[]
  first_found_at: string
  closed_at: string | null
  closed_reason: string | null
  reopen_count: number
  accepted_by_id: number | null
  accepted_at: string | null
  accepted_reason: string | null
  accepted_until: string | null
  is_accepted: boolean
  days_open: number
  scan_name: string | null
}

export type RiskSortKey = 'level' | 'days_open' | 'repo' | 'score'

export interface PaginatedRisks {
  items: RiskRecord[]
  total: number
  page: number
  page_size: number
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<{ access_token: string } | TotpChallenge>('/auth/login', {
        method: 'POST', body: JSON.stringify({ email, password })
      }),
    totpVerify: (totp_session_token: string, code: string) =>
      request<{ access_token: string }>('/auth/totp/verify', {
        method: 'POST', body: JSON.stringify({ totp_session_token, code })
      }),
    totpDisable: (code: string) =>
      request<void>('/auth/totp/disable', { method: 'POST', body: JSON.stringify({ code }) }),
    totpStatus: () => request<{ totp_enabled: boolean }>('/auth/totp/status'),
    me: () => request<User>('/auth/me'),
    register: (data: { email: string; display_name: string; password: string; role: UserRole }) =>
      request<User>('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
  },

  dashboard: {
    get: () => request<DashboardStats>('/dashboard'),
    exposureHistory: (days?: number) =>
      request<ExposureHistory>(`/dashboard/exposure-history${days ? `?days=${days}` : ''}`),
  },

  hosts: {
    list: () => request<Host[]>('/hosts'),
    get: (id: number) => request<Host>(`/hosts/${id}`),
    update: (id: number, data: Partial<Host>) =>
      request<Host>(`/hosts/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: number) => request<void>(`/hosts/${id}`, { method: 'DELETE' }),
  },

  alerts: {
    list: (params?: { host_id?: number; severity?: AlertSeverity; acknowledged?: boolean; limit?: number }) => {
      const q = new URLSearchParams()
      if (params?.host_id) q.set('host_id', String(params.host_id))
      if (params?.severity) q.set('severity', params.severity)
      if (params?.acknowledged !== undefined) q.set('acknowledged', String(params.acknowledged))
      if (params?.limit) q.set('limit', String(params.limit))
      return request<Alert[]>(`/alerts?${q}`)
    },
    acknowledge: (id: number, ack = true) =>
      request<Alert>(`/alerts/${id}/acknowledge`, { method: 'PATCH', body: JSON.stringify({ acknowledged: ack }) }),
    acknowledgeBulk: (ids: number[], ack = true) =>
      request<void>(`/alerts/acknowledge-bulk`, { method: 'PATCH', body: JSON.stringify({ alert_ids: ids, acknowledged: ack }) }),
  },

  scans: {
    list: (params?: { host_id?: number }) => {
      const q = new URLSearchParams()
      if (params?.host_id) q.set('host_id', String(params.host_id))
      return request<Scan[]>(`/scans?${q}`)
    },
  },

  configs: {
    list: () => request<ConfigTemplate[]>('/config-templates'),
    get: (id: number) => request<ConfigTemplate>(`/config-templates/${id}`),
    create: (data: { name: string; description?: string; toml_content: string }) =>
      request<ConfigTemplate>('/config-templates', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: number, data: Partial<ConfigTemplate>) =>
      request<ConfigTemplate>(`/config-templates/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: number) => request<void>(`/config-templates/${id}`, { method: 'DELETE' }),
    assign: (tmplId: number, hostId: number) =>
      request<void>(`/config-templates/${tmplId}/assign/${hostId}`, { method: 'POST' }),
    forHost: (hostId: number) => request<ConfigTemplate | null>(`/config-templates/for-host/${hostId}`),
    validate: (toml_content: string, signal?: AbortSignal) =>
      request<LintResult>('/config-templates/validate', {
        method: 'POST', body: JSON.stringify({ toml_content }), signal,
      }),
  },

  ingest: {
    cooldown: (hostname: string) =>
      request<CooldownEntry[]>(`/ingest/cooldown?hostname=${encodeURIComponent(hostname)}`),
  },

  cooldown: {
    list: (params?: { host_id?: number; fleet_wide?: boolean }) => {
      const q = new URLSearchParams()
      if (params?.host_id) q.set('host_id', String(params.host_id))
      if (params?.fleet_wide !== undefined) q.set('fleet_wide', String(params.fleet_wide))
      return request<CooldownEntry[]>(`/cooldown?${q}`)
    },
    create: (data: {
      package_name: string; package_version?: string
      ecosystem?: Ecosystem; host_id?: number | null
      note?: string; expires_at?: string
    }) => request<CooldownEntry>('/cooldown', { method: 'POST', body: JSON.stringify(data) }),
    delete: (id: number) => request<void>(`/cooldown/${id}`, { method: 'DELETE' }),
  },

  apiKeys: {
    list: () => request<ApiKey[]>('/api-keys'),
    create: (data: { name: string }) =>
      request<ApiKey>('/api-keys', { method: 'POST', body: JSON.stringify(data) }),
    revoke: (id: number) => request<void>(`/api-keys/${id}`, { method: 'DELETE' }),
  },

  users: {
    list: () => request<User[]>('/users'),
    update: (id: number, data: Partial<User & { password: string }>) =>
      request<User>(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: number) =>
      request<void>(`/users/${id}`, { method: 'DELETE' }),
    resetTotp: (id: number) =>
      request<User>(`/users/${id}/reset-totp`, { method: 'POST' }),
  },

  systemSettings: {
    list: () => request<SystemSetting[]>('/system-settings'),
    update: (updates: Record<string, string | null>) =>
      request<SystemSetting[]>('/system-settings', { method: 'PATCH', body: JSON.stringify({ updates }) }),
  },

  repoCredentials: {
    list: () => request<RepoCredential[]>('/repo-credentials'),
    create: (data: { name: string; credential_type: CredentialType; credential_value?: string | null; ssh_key_passphrase?: string }) =>
      request<RepoCredential>('/repo-credentials', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: number, data: { name?: string; credential_type?: CredentialType; credential_value?: string; ssh_key_passphrase?: string }) =>
      request<RepoCredential>(`/repo-credentials/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: number) => request<void>(`/repo-credentials/${id}`, { method: 'DELETE' }),
  },

  repoScans: {
    list: () => request<RepoScan[]>('/repo-scans'),
    get: (id: number) => request<RepoScan>(`/repo-scans/${id}`),
    create: (data: {
      name: string; url: string; branch: string
      credential_id?: number | null
      cron_schedule?: string | null; cron_timezone?: string | null; is_enabled?: boolean
      config_template_id?: number | null; pa_version?: string | null; scan_flags?: string | null; subfolder?: string | null
      min_notify_severity?: AlertSeverity; notify_recipients?: string[]
    }) => request<RepoScan>('/repo-scans', { method: 'POST', body: JSON.stringify(data) }),
    update: (id: number, data: Partial<RepoScan>) =>
      request<RepoScan>(`/repo-scans/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id: number) => request<void>(`/repo-scans/${id}`, { method: 'DELETE' }),
    trigger: (id: number) => request<RepoScanResult>(`/repo-scans/${id}/trigger`, { method: 'POST' }),
    results: (id: number) => request<RepoScanResult[]>(`/repo-scans/${id}/results`),
    allResults: (limit?: number) => request<RepoScanResultWithName[]>(`/repo-scans/results${limit ? `?limit=${limit}` : ''}`),
    scanOptions: () => request<ScanOptions>('/repo-scans/scan-options'),
    headlines: () => request<RepoScanHeadline[]>('/repo-scans/headlines'),
    exposureHistory: (id: number, days?: number) =>
      request<ExposureHistory>(`/repo-scans/${id}/exposure-history${days ? `?days=${days}` : ''}`),
  },

  findings: {
    list: (params?: {
      severity?: AlertSeverity[]
      breach?: boolean
      accepted?: boolean
      repo_scan_id?: number
      page?: number
      page_size?: number
      sort?: FindingSortKey
      sort_dir?: SortDir
    }): Promise<PaginatedFindings> => {
      const q = new URLSearchParams()
      if (params?.severity) params.severity.forEach(s => q.append('severity', s))
      if (params?.breach !== undefined) q.set('breach', String(params.breach))
      if (params?.accepted !== undefined) q.set('accepted', String(params.accepted))
      if (params?.repo_scan_id !== undefined) q.set('repo_scan_id', String(params.repo_scan_id))
      if (params?.page !== undefined) q.set('page', String(params.page))
      if (params?.page_size !== undefined) q.set('page_size', String(params.page_size))
      if (params?.sort) q.set('sort', params.sort)
      if (params?.sort_dir) q.set('sort_dir', params.sort_dir)
      const qs = q.toString()
      return request<PaginatedFindings>(`/findings${qs ? `?${qs}` : ''}`)
    },
    listAllForRepo: (repoScanId: number): Promise<FindingRecord[]> =>
      request<FindingRecord[]>(`/repo-scans/${repoScanId}/findings`),
    accept: (id: number, body: { reason: string; accepted_until?: string }): Promise<FindingRecord> =>
      request<FindingRecord>(`/findings/${id}/accept`, { method: 'POST', body: JSON.stringify(body) }),
    revokeAccept: (id: number): Promise<FindingRecord> =>
      request<FindingRecord>(`/findings/${id}/accept`, { method: 'DELETE' }),
  },

  risks: {
    list: (params?: {
      level?: ('critical' | 'warning' | 'info')[]
      accepted?: boolean
      repo_scan_id?: number
      page?: number
      page_size?: number
      sort?: RiskSortKey
      sort_dir?: SortDir
    }): Promise<PaginatedRisks> => {
      const q = new URLSearchParams()
      if (params?.level) params.level.forEach(l => q.append('level', l))
      if (params?.accepted !== undefined) q.set('accepted', String(params.accepted))
      if (params?.repo_scan_id !== undefined) q.set('repo_scan_id', String(params.repo_scan_id))
      if (params?.page !== undefined) q.set('page', String(params.page))
      if (params?.page_size !== undefined) q.set('page_size', String(params.page_size))
      if (params?.sort) q.set('sort', params.sort)
      if (params?.sort_dir) q.set('sort_dir', params.sort_dir)
      const qs = q.toString()
      return request<PaginatedRisks>(`/risks${qs ? `?${qs}` : ''}`)
    },
    listAllForRepo: (repoScanId: number): Promise<RiskRecord[]> =>
      request<RiskRecord[]>(`/repo-scans/${repoScanId}/risks`),
    accept: (id: number, body: { reason: string; accepted_until?: string }): Promise<RiskRecord> =>
      request<RiskRecord>(`/risks/${id}/accept`, { method: 'POST', body: JSON.stringify(body) }),
    revokeAccept: (id: number): Promise<RiskRecord> =>
      request<RiskRecord>(`/risks/${id}/accept`, { method: 'DELETE' }),
  },
}
