import type { ScanFlag } from '@/lib/api'

// This module only needs to parse strings that assembleScanArgs() itself produced.
// It does not attempt to handle arbitrary CLI syntax (e.g. --flag value, --flag=,
// --no-flag, etc.).

// Matches a POSIX sh single-quoted token including '\'' escape sequences.
// assembleScanArgs() produces e.g. --flag='req'\''s.txt':
//   'req' (sq-chunk) + \' (bare escaped quote) + 's.txt' (sq-chunk).
// One or more adjacent chunks/escapes.
export const SQ_TOKEN = `(?:'[^']*'|\\\\')+`

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function unquoteSq(s: string): string {
  let result = ''
  let i = 0
  while (i < s.length) {
    if (s[i] === "'") {
      const end = s.indexOf("'", i + 1)
      if (end === -1) { result += s.slice(i + 1); break }
      result += s.slice(i + 1, end)
      i = end + 1
    } else if (s[i] === '\\' && s[i + 1] === "'") {
      result += "'"
      i += 2
    } else {
      result += s[i++]
    }
  }
  return result
}

export type CompiledFlag = ScanFlag & {
  matchRe: RegExp
}

export function compileFlags(flags: ScanFlag[]): CompiledFlag[] {
  return flags.map(flag => {
    const f = escapeRe(flag.cli_flag)
    return flag.type === 'bool'
      ? { ...flag, matchRe: new RegExp(`(?:^|\\s)${f}(?=\\s|$)`) }
      : { ...flag, matchRe: new RegExp(`(?:^|\\s)${f}=(${SQ_TOKEN}|\\S+)`, 'g') }
  })
}

export type ParseResult = { bools: Record<string, boolean>; strs: Record<string, string> }

function _parseScanArgs(raw: string, compiled: CompiledFlag[]): ParseResult {
  const bools: Record<string, boolean> = {}
  const strs: Record<string, string> = {}
  for (const flag of compiled) {
    if (flag.type === 'bool') {
      if (flag.matchRe.test(raw)) bools[flag.name] = true
    } else if (flag.type === 'str') {
      flag.matchRe.lastIndex = 0
      let last: string | undefined
      let m: RegExpExecArray | null
      while ((m = flag.matchRe.exec(raw)) !== null) last = m[1]
      if (last !== undefined) {
        const value = last.startsWith("'") ? unquoteSq(last) : last
        if (value.trim()) strs[flag.name] = value
      }
    }
  }
  return { bools, strs }
}

function isCompiledFlags(flags: ScanFlag[] | CompiledFlag[]): flags is CompiledFlag[] {
  // Empty array requires no compilation and is treated as already-compiled.
  return flags.length === 0 || 'matchRe' in flags[0]
}

export function parseScanArgs(raw: string, flags: CompiledFlag[]): ParseResult
export function parseScanArgs(raw: string, flags: ScanFlag[]): ParseResult
export function parseScanArgs(raw: string, flags: ScanFlag[] | CompiledFlag[]): ParseResult {
  return _parseScanArgs(raw, isCompiledFlags(flags) ? flags : compileFlags(flags))
}

export type ScanArgsState = { bools: Record<string, boolean>; strs: Record<string, string> }
export type ScanArgsAction =
  | { type: 'toggle_bool'; name: string; exclusions: string[][]; flagByName: Map<string, ScanFlag> }
  | { type: 'set_str'; name: string; val: string; exclusions: string[][]; flagByName: Map<string, ScanFlag> }

export function clearExcluded(
  name: string,
  bools: Record<string, boolean>,
  strs: Record<string, string>,
  exclusions: string[][],
  flagByName: Map<string, ScanFlag>,
): void {
  for (const pair of exclusions) {
    if (!pair.includes(name)) continue
    const other = pair.find(p => p !== name)
    if (!other) continue
    const otherFlag = flagByName.get(other)
    if (otherFlag?.type === 'bool') bools[other] = false
    else if (otherFlag?.type === 'str') delete strs[other]
  }
}

export function scanArgsReducer(state: ScanArgsState, action: ScanArgsAction): ScanArgsState {
  if (action.type === 'toggle_bool') {
    const bools = { ...state.bools, [action.name]: !state.bools[action.name] }
    const strs = { ...state.strs }
    if (bools[action.name]) clearExcluded(action.name, bools, strs, action.exclusions, action.flagByName)
    return { bools, strs }
  }
  if (action.type === 'set_str') {
    const strs = { ...state.strs }
    const bools = { ...state.bools }
    if (action.val.trim()) {
      strs[action.name] = action.val
      clearExcluded(action.name, bools, strs, action.exclusions, action.flagByName)
    } else {
      delete strs[action.name]
    }
    return { bools, strs }
  }
  const _exhaustive: never = action
  throw new Error(`unhandled action type: ${(_exhaustive as ScanArgsAction).type}`)
}

export function assembleScanArgs(
  bools: Record<string, boolean>,
  strs: Record<string, string>,
  flags: ScanFlag[],
): string {
  const parts: string[] = []
  for (const flag of flags) {
    if (flag.type === 'bool' && bools[flag.name]) {
      parts.push(flag.cli_flag)
    } else if (flag.type === 'str' && strs[flag.name]?.trim()) {
      const raw = strs[flag.name]
      const quoted = `'${raw.split("'").join("'\\''")}'`
      parts.push(`${flag.cli_flag}=${quoted}`)
    }
  }
  return parts.join(' ')
}
