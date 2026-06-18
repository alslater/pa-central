import { timeAgo } from '@/components/ui'

function isoSecondsAgo(n: number) {
  return new Date(Date.now() - n * 1000).toISOString()
}

describe('timeAgo', () => {
  it('returns "just now" for timestamps under 1 minute ago', () => {
    expect(timeAgo(isoSecondsAgo(30))).toBe('just now')
    expect(timeAgo(isoSecondsAgo(0))).toBe('just now')
  })

  it('returns minutes for timestamps 1–59 minutes ago', () => {
    expect(timeAgo(isoSecondsAgo(60))).toBe('1m ago')
    expect(timeAgo(isoSecondsAgo(90))).toBe('1m ago')
    expect(timeAgo(isoSecondsAgo(59 * 60))).toBe('59m ago')
  })

  it('returns hours for timestamps 1–23 hours ago', () => {
    expect(timeAgo(isoSecondsAgo(3600))).toBe('1h ago')
    expect(timeAgo(isoSecondsAgo(23 * 3600))).toBe('23h ago')
  })

  it('returns days for timestamps 24+ hours ago', () => {
    expect(timeAgo(isoSecondsAgo(24 * 3600))).toBe('1d ago')
    expect(timeAgo(isoSecondsAgo(7 * 24 * 3600))).toBe('7d ago')
  })

  it('handles ISO strings without a Z suffix', () => {
    const withoutZ = new Date(Date.now() - 5000).toISOString().replace('Z', '')
    expect(timeAgo(withoutZ)).toBe('just now')
  })

  it('handles ISO strings with a Z suffix', () => {
    const withZ = new Date(Date.now() - 5000).toISOString()
    expect(timeAgo(withZ)).toBe('just now')
  })

  it('handles ISO strings with an explicit UTC offset (+00:00)', () => {
    // 2 minutes ago expressed as +00:00 — must not have Z appended
    const ts = new Date(Date.now() - 2 * 60000).toISOString().replace('Z', '+00:00')
    expect(timeAgo(ts)).toBe('2m ago')
  })

  it('handles ISO strings with a positive offset (+01:00)', () => {
    // Express "5 minutes ago" as a +01:00 timestamp
    const utcMs = Date.now() - 5 * 60000
    const offsetMs = 60 * 60000 // +01:00 in ms
    const localIso = new Date(utcMs + offsetMs).toISOString().replace('Z', '+01:00')
    expect(timeAgo(localIso)).toBe('5m ago')
  })
})
