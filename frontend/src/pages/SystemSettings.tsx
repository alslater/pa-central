import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
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
  { key: 'scan_result_retention_days',  label: 'Retention (days)',  hint: 'e.g. 30', type: 'int' },
  { key: 'scan_result_retention_count', label: 'Retention (count)', hint: 'e.g. 100', type: 'int' },
  { key: 'app_base_url',         label: 'App Base URL',          hint: 'https://pa-central.example.com', type: 'string' },
  { key: 'default_cron_timezone', label: 'Default cron timezone', hint: 'IANA name, e.g. Europe/London — leave blank for UTC', type: 'string' },
]

const SECRET_KEYS = new Set(KNOWN_SETTINGS.filter(s => s.type === 'secret').map(s => s.key))

export default function SystemSettings() {
  const [settings, setSettings] = useState<Record<string, string>>({})
  // Tracks which secret fields the user has actually typed into this session.
  // Secret fields not in this set are excluded from the PATCH so we never
  // overwrite a stored secret with an empty string.
  const [dirtySecrets, setDirtySecrets] = useState<Set<string>>(new Set())
  const [saving, setSaving] = useState(false)
  const { show, Toast } = useToast()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  useEffect(() => {
    api.systemSettings.list().then(rows => {
      const m: Record<string, string> = {}
      for (const r of rows) m[r.key] = r.value ?? ''
      setSettings(m)
    }).catch(e => show(e.message, 'err'))
  }, [])

  const set = (key: string, val: string) => {
    setSettings(prev => ({ ...prev, [key]: val }))
    if (SECRET_KEYS.has(key)) setDirtySecrets(prev => new Set(prev).add(key))
  }

  const save = async () => {
    setSaving(true)
    const updates: Record<string, string | null> = {}
    for (const { key } of KNOWN_SETTINGS) {
      if (SECRET_KEYS.has(key) && !dirtySecrets.has(key)) continue
      // Only patch keys the user has actually loaded or edited; skip keys that
      // were never populated so we don't overwrite DB values with null.
      if (!(key in settings)) continue
      updates[key] = settings[key] === '' ? null : settings[key]
    }
    try {
      await api.systemSettings.update(updates)
      show('Settings saved')
      setDirtySecrets(new Set())
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
        subtitle="Email / SMTP configuration and scan retention"
        action={isAdmin ? <Button variant="primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button> : undefined}
      />
      {Toast}
      <div className="p-6 px-7 max-w-[600px]">
        <Card>
          <div className="px-6 py-5 flex flex-col gap-4">
            <section>
              <h3 className="text-style-caption mb-3">Email / SMTP</h3>
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
                <TimezoneField
                  label="Default cron timezone"
                  value={settings['default_cron_timezone'] ?? ''}
                  onChange={v => set('default_cron_timezone', v)}
                  placeholder="leave blank for UTC"
                />
              </div>
            </section>
          </div>
        </Card>
      </div>
    </Shell>
  )
}
