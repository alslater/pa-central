import { parseScanArgs, assembleScanArgs, unquoteSq, scanArgsReducer } from '@/lib/scanArgs'
import type { ScanFlag } from '@/lib/api'

const BOOL_UNPINNED: ScanFlag = { name: 'scan_unpinned', cli_flag: '--scan-unpinned', type: 'bool', help: '' }
const BOOL_INSTALLED: ScanFlag = { name: 'scan_installed', cli_flag: '--scan-installed', type: 'bool', help: '' }
const STR_REQUIREMENTS: ScanFlag = { name: 'requirements', cli_flag: '--requirements', type: 'str', help: '' }

const FLAGS = [BOOL_UNPINNED, BOOL_INSTALLED, STR_REQUIREMENTS]
const EXCLUSIONS: string[][] = [['scan_installed', 'requirements']]

describe('unquoteSq', () => {
  it('strips outer single quotes', () => {
    expect(unquoteSq("'hello'")).toBe('hello')
  })

  it("unescapes internal '\\'' sequences", () => {
    expect(unquoteSq("'it'\\''s'")).toBe("it's")
    expect(unquoteSq("'a'\\''b'\\''c'")).toBe("a'b'c")
  })

  it('handles unmatched opening quote without looping', () => {
    expect(unquoteSq("'unterminated")).toBe('unterminated')
  })
})

describe('assembleScanArgs', () => {
  it('emits a bool flag when checked', () => {
    expect(assembleScanArgs({ scan_unpinned: true }, {}, FLAGS)).toBe('--scan-unpinned')
  })

  it('emits nothing for unchecked bools', () => {
    expect(assembleScanArgs({}, {}, FLAGS)).toBe('')
  })

  it('single-quotes a simple str value', () => {
    expect(assembleScanArgs({}, { requirements: 'req.txt' }, FLAGS)).toBe("--requirements='req.txt'")
  })

  it('escapes single quotes inside str values', () => {
    const out = assembleScanArgs({}, { requirements: "req's.txt" }, FLAGS)
    expect(out).toBe("--requirements='req'\\''s.txt'")
  })

  it('escapes str values containing spaces', () => {
    const out = assembleScanArgs({}, { requirements: 'requirements dev.txt' }, FLAGS)
    expect(out).toBe("--requirements='requirements dev.txt'")
  })

  it('omits str flag when value is empty string', () => {
    expect(assembleScanArgs({}, { requirements: '' }, FLAGS)).toBe('')
  })

  it('omits str flag when value is whitespace-only', () => {
    expect(assembleScanArgs({}, { requirements: '   ' }, FLAGS)).toBe('')
  })
})

describe('parseScanArgs', () => {
  it('parses a single bool flag', () => {
    const { bools, strs } = parseScanArgs('--scan-unpinned', FLAGS)
    expect(bools).toEqual({ scan_unpinned: true })
    expect(strs).toEqual({})
  })

  it('parses multiple bool flags', () => {
    const { bools } = parseScanArgs('--scan-unpinned --scan-installed', FLAGS)
    expect(bools.scan_unpinned).toBe(true)
    expect(bools.scan_installed).toBe(true)
  })

  it('parses a simple unquoted str value', () => {
    const { strs } = parseScanArgs('--requirements=req.txt', FLAGS)
    expect(strs.requirements).toBe('req.txt')
  })

  it('parses a single-quoted str value', () => {
    const { strs } = parseScanArgs("--requirements='req.txt'", FLAGS)
    expect(strs.requirements).toBe('req.txt')
  })

  it('parses a single-quoted value containing spaces', () => {
    const { strs } = parseScanArgs("--requirements='requirements dev.txt'", FLAGS)
    expect(strs.requirements).toBe('requirements dev.txt')
  })

  it("parses a single-quoted value containing escaped single quotes", () => {
    const { strs } = parseScanArgs("--requirements='req'\\''s.txt'", FLAGS)
    expect(strs.requirements).toBe("req's.txt")
  })

  it('does not match --requirements-dev as --requirements', () => {
    const { strs } = parseScanArgs('--requirements-dev=req.txt', FLAGS)
    expect(strs.requirements).toBeUndefined()
  })

  it('does not hang or throw on a malformed single-quoted value (unmatched quote)', () => {
    // The critical requirement is that the call completes without hanging.
    const { strs } = parseScanArgs("--requirements='unterminated", FLAGS)
    expect(typeof strs.requirements === 'string' || strs.requirements === undefined).toBe(true)
  })

  it('uses last value when a str flag appears multiple times (last-wins)', () => {
    const { strs } = parseScanArgs('--requirements=first.txt --requirements=last.txt', FLAGS)
    expect(strs.requirements).toBe('last.txt')
  })

  it('does not match --requirements with no following value', () => {
    const { strs } = parseScanArgs('--scan-unpinned --requirements', FLAGS)
    expect(strs.requirements).toBeUndefined()
  })
})

describe('round-trip (assemble then parse)', () => {
  it('round-trips bool flags', () => {
    const assembled = assembleScanArgs({ scan_unpinned: true, scan_installed: true }, {}, FLAGS)
    const { bools } = parseScanArgs(assembled, FLAGS)
    expect(bools.scan_unpinned).toBe(true)
    expect(bools.scan_installed).toBe(true)
  })

  it('round-trips a simple str value', () => {
    const assembled = assembleScanArgs({}, { requirements: 'req.txt' }, FLAGS)
    const { strs } = parseScanArgs(assembled, FLAGS)
    expect(strs.requirements).toBe('req.txt')
  })

  it('round-trips a str value with spaces', () => {
    const assembled = assembleScanArgs({}, { requirements: 'requirements dev.txt' }, FLAGS)
    const { strs } = parseScanArgs(assembled, FLAGS)
    expect(strs.requirements).toBe('requirements dev.txt')
  })

  it("round-trips a str value with single quotes", () => {
    const assembled = assembleScanArgs({}, { requirements: "req's.txt" }, FLAGS)
    const { strs } = parseScanArgs(assembled, FLAGS)
    expect(strs.requirements).toBe("req's.txt")
  })

  it('whitespace-only str value is omitted from assembly and not parsed back', () => {
    const assembled = assembleScanArgs({}, { requirements: '   ' }, FLAGS)
    expect(assembled).toBe('')
    const { strs } = parseScanArgs(assembled, FLAGS)
    expect('requirements' in strs).toBe(false)
  })
})

// Helper that mirrors ScanArgsField's isExcluded logic using key-presence for strs.
function isExcluded(
  flagName: string,
  bools: Record<string, boolean>,
  strs: Record<string, string>,
  exclusions: string[][],
  flags: ScanFlag[],
): boolean {
  const flagByName = new Map(flags.map(f => [f.name, f]))
  for (const pair of exclusions) {
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

describe('exclusions', () => {
  it('scan_installed (bool set) excludes requirements', () => {
    expect(isExcluded('requirements', { scan_installed: true }, {}, EXCLUSIONS, FLAGS)).toBe(true)
  })

  it('requirements (non-empty str) excludes scan_installed', () => {
    expect(isExcluded('scan_installed', {}, { requirements: 'req.txt' }, EXCLUSIONS, FLAGS)).toBe(true)
  })

  it('scan_unpinned is not excluded by scan_installed', () => {
    expect(isExcluded('scan_unpinned', { scan_installed: true }, {}, EXCLUSIONS, FLAGS)).toBe(false)
  })

  it('requirements key absent means scan_installed is not excluded', () => {
    // The invariant: parseScanArgs and setStr never store an empty-string value;
    // they omit the key entirely. isExcluded uses key-presence, so absent == not set.
    expect(isExcluded('scan_installed', {}, {}, EXCLUSIONS, FLAGS)).toBe(false)
  })

  it('parseScanArgs does not set requirements key for --requirements=\'\'', () => {
    const { strs } = parseScanArgs("--requirements=''", FLAGS)
    expect('requirements' in strs).toBe(false)
  })

  it('parseScanArgs does not set requirements key for whitespace-only value', () => {
    const { strs } = parseScanArgs("--requirements='   '", FLAGS)
    expect('requirements' in strs).toBe(false)
  })

  it('parseScanArgs with empty value leaves scan_installed unexcluded', () => {
    const { strs, bools } = parseScanArgs("--requirements=''", FLAGS)
    expect(isExcluded('scan_installed', bools, strs, EXCLUSIONS, FLAGS)).toBe(false)
  })
})

describe('scanArgsReducer', () => {
  const flagByName = new Map(FLAGS.map(f => [f.name, f]))

  it('toggle_bool on: sets bool true', () => {
    const state = { bools: {}, strs: {} }
    const next = scanArgsReducer(state, { type: 'toggle_bool', name: 'scan_unpinned', exclusions: EXCLUSIONS, flagByName })
    expect(next.bools.scan_unpinned).toBe(true)
  })

  it('toggle_bool off: sets bool false', () => {
    const state = { bools: { scan_unpinned: true }, strs: {} }
    const next = scanArgsReducer(state, { type: 'toggle_bool', name: 'scan_unpinned', exclusions: EXCLUSIONS, flagByName })
    expect(next.bools.scan_unpinned).toBe(false)
  })

  it('toggle_bool on clears mutually-exclusive str', () => {
    const state = { bools: {}, strs: { requirements: 'req.txt' } }
    const next = scanArgsReducer(state, { type: 'toggle_bool', name: 'scan_installed', exclusions: EXCLUSIONS, flagByName })
    expect(next.bools.scan_installed).toBe(true)
    expect('requirements' in next.strs).toBe(false)
  })

  it('toggle_bool off does not clear mutually-exclusive str', () => {
    const state = { bools: { scan_installed: true }, strs: { requirements: 'req.txt' } }
    const next = scanArgsReducer(state, { type: 'toggle_bool', name: 'scan_installed', exclusions: EXCLUSIONS, flagByName })
    expect(next.bools.scan_installed).toBe(false)
    expect(next.strs.requirements).toBe('req.txt')
  })

  it('set_str with value sets str and clears mutually-exclusive bool', () => {
    const state = { bools: { scan_installed: true }, strs: {} }
    const next = scanArgsReducer(state, { type: 'set_str', name: 'requirements', val: 'req.txt', exclusions: EXCLUSIONS, flagByName })
    expect(next.strs.requirements).toBe('req.txt')
    expect(next.bools.scan_installed).toBe(false)
  })

  it('set_str with empty value removes str without touching bools', () => {
    const state = { bools: { scan_unpinned: true }, strs: { requirements: 'req.txt' } }
    const next = scanArgsReducer(state, { type: 'set_str', name: 'requirements', val: '', exclusions: EXCLUSIONS, flagByName })
    expect('requirements' in next.strs).toBe(false)
    expect(next.bools.scan_unpinned).toBe(true)
  })

  it('set_str with whitespace-only value removes str', () => {
    const state = { bools: {}, strs: { requirements: 'req.txt' } }
    const next = scanArgsReducer(state, { type: 'set_str', name: 'requirements', val: '   ', exclusions: EXCLUSIONS, flagByName })
    expect('requirements' in next.strs).toBe(false)
  })

  it('does not mutate original state', () => {
    const state = { bools: { scan_installed: true }, strs: { requirements: 'req.txt' } }
    const boolsBefore = { ...state.bools }
    const strsBefore = { ...state.strs }
    scanArgsReducer(state, { type: 'toggle_bool', name: 'scan_installed', exclusions: EXCLUSIONS, flagByName })
    expect(state.bools).toEqual(boolsBefore)
    expect(state.strs).toEqual(strsBefore)
  })
})
