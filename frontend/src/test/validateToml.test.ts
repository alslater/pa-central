import { validateToml } from '@/components/TomlEditor'

describe('validateToml', () => {
  it('returns null for valid TOML', () => {
    expect(validateToml('[section]\nkey = "value"')).toBeNull()
    expect(validateToml('port = 587\nhost = "smtp.example.com"')).toBeNull()
    expect(validateToml('')).toBeNull()
  })

  it('returns an error string for invalid TOML', () => {
    expect(validateToml('[unclosed')).not.toBeNull()
    expect(validateToml('key = ')).not.toBeNull()
    expect(validateToml('= no key')).not.toBeNull()
  })

  it('returns a non-empty string message on error', () => {
    const result = validateToml('[bad')
    expect(typeof result).toBe('string')
    expect(result!.length).toBeGreaterThan(0)
  })

  it('accepts multi-section valid TOML', () => {
    const toml = `
[osv]
cache_ttl_hours = 24

[watch]
enable_cache_monitoring = true

[alerts]
desktop_notifications = false
min_severity_for_desktop = "MEDIUM"
    `.trim()
    expect(validateToml(toml)).toBeNull()
  })

  it('accepts arrays and inline tables', () => {
    expect(validateToml('tags = ["a", "b", "c"]')).toBeNull()
    expect(validateToml('point = { x = 1, y = 2 }')).toBeNull()
  })
})
