import { useEffect, useRef, useMemo, useState } from 'react'
import { parse as parseToml } from 'smol-toml'
import { EditorState } from '@codemirror/state'
import { EditorView, keymap, lineNumbers, highlightActiveLine, drawSelection } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { StreamLanguage, syntaxHighlighting, defaultHighlightStyle } from '@codemirror/language'
import { toml } from '@codemirror/legacy-modes/mode/toml'
import {
  abcdef, androidstudio, atomone, aura, basicDark, basicLight, bbedit,
  bespin, consoleDark, copilot, darcula, dracula, duotoneDark, duotoneLight,
  eclipse, githubDark, githubLight, gruvboxDark, gruvboxLight,
  materialDark, materialLight, monokai, monokaiDimmed, noctisLilac, nord,
  okaidia, quietlight, solarizedDark, solarizedLight, sublime, tokyoNight,
  tokyoNightDay, tokyoNightStorm, tomorrowNightBlue, vscodeDark, vscodeLight,
  xcodeDark, xcodeLight,
} from '@uiw/codemirror-themes-all'
import { oneDark } from '@codemirror/theme-one-dark'
import type { Extension } from '@codemirror/state'

export function validateToml(content: string): string | null {
  try { parseToml(content); return null }
  catch (e: any) { return e.message ?? 'Invalid TOML' }
}

// ── Available themes ──────────────────────────────────────────────────────────

export const EDITOR_THEMES: Record<string, { label: string; ext: Extension; dark: boolean }> = {
  'ds-default':       { label: 'Default (DS)',    ext: [] as Extension,   dark: true  },
  'vscode-dark':      { label: 'VS Code Dark',    ext: vscodeDark,        dark: true  },
  'vscode-light':     { label: 'VS Code Light',   ext: vscodeLight,       dark: false },
  'github-dark':      { label: 'GitHub Dark',     ext: githubDark,        dark: true  },
  'github-light':     { label: 'GitHub Light',    ext: githubLight,       dark: false },
  'one-dark':         { label: 'One Dark',        ext: oneDark,           dark: true  },
  'dracula':          { label: 'Dracula',         ext: dracula,           dark: true  },
  'tokyo-night':      { label: 'Tokyo Night',     ext: tokyoNight,        dark: true  },
  'tokyo-night-day':  { label: 'Tokyo Night Day', ext: tokyoNightDay,     dark: false },
  'tokyo-night-storm':{ label: 'Tokyo Storm',     ext: tokyoNightStorm,   dark: true  },
  'nord':             { label: 'Nord',            ext: nord,              dark: true  },
  'gruvbox-dark':     { label: 'Gruvbox Dark',    ext: gruvboxDark,       dark: true  },
  'gruvbox-light':    { label: 'Gruvbox Light',   ext: gruvboxLight,      dark: false },
  'monokai':          { label: 'Monokai',         ext: monokai,           dark: true  },
  'monokai-dimmed':   { label: 'Monokai Dimmed',  ext: monokaiDimmed,     dark: true  },
  'solarized-dark':   { label: 'Solarized Dark',  ext: solarizedDark,     dark: true  },
  'solarized-light':  { label: 'Solarized Light', ext: solarizedLight,    dark: false },
  'material-dark':    { label: 'Material Dark',   ext: materialDark,      dark: true  },
  'material-light':   { label: 'Material Light',  ext: materialLight,     dark: false },
  'sublime':          { label: 'Sublime',         ext: sublime,           dark: true  },
  'aura':             { label: 'Aura',            ext: aura,              dark: true  },
  'atomone':          { label: 'Atom One',        ext: atomone,           dark: true  },
  'darcula':          { label: 'Darcula',         ext: darcula,           dark: true  },
  'android-studio':   { label: 'Android Studio',  ext: androidstudio,     dark: true  },
  'tomorrow-night':   { label: 'Tomorrow Night',  ext: tomorrowNightBlue, dark: true  },
  'duotone-dark':     { label: 'Duotone Dark',    ext: duotoneDark,       dark: true  },
  'duotone-light':    { label: 'Duotone Light',   ext: duotoneLight,      dark: false },
  'xcode-dark':       { label: 'Xcode Dark',      ext: xcodeDark,         dark: true  },
  'xcode-light':      { label: 'Xcode Light',     ext: xcodeLight,        dark: false },
  'okaidia':          { label: 'Okaidia',         ext: okaidia,           dark: true  },
  'bespin':           { label: 'Bespin',          ext: bespin,            dark: true  },
  'eclipse':          { label: 'Eclipse',         ext: eclipse,           dark: false },
  'bbedit':           { label: 'BBEdit',          ext: bbedit,            dark: false },
  'noctis-lilac':     { label: 'Noctis Lilac',    ext: noctisLilac,       dark: false },
  'basic-dark':       { label: 'Basic Dark',      ext: basicDark,         dark: true  },
  'basic-light':      { label: 'Basic Light',     ext: basicLight,        dark: false },
  'console-dark':     { label: 'Console Dark',    ext: consoleDark,       dark: true  },
  'copilot':          { label: 'Copilot',         ext: copilot,           dark: true  },
  'quietlight':       { label: 'Quiet Light',     ext: quietlight,        dark: false },
  'abcdef':           { label: 'ABCDEF',          ext: abcdef,            dark: true  },
}

const THEME_KEY = 'pa-editor-theme'

// Default DS theme — uses CSS vars so it follows the app's dark/light token set.
const dsTheme = EditorView.theme({
  '&': {
    fontSize: '12px',
    fontFamily: 'var(--font-mono)',
    background: 'transparent',
    color: 'var(--text-primary)',
    height: '100%',
  },
  '.cm-content': { padding: '12px 0', caretColor: 'hsl(var(--brand))' },
  '.cm-line': { padding: '0 14px' },
  '.cm-activeLine': { background: 'hsl(var(--muted)/0.4)' },
  '.cm-gutters': {
    background: 'hsl(var(--muted)/0.3)',
    borderRight: '1px solid var(--border)',
    color: 'var(--text-muted)',
    minWidth: '2.8em',
  },
  '.cm-gutterElement': { padding: '0 6px 0 8px' },
  '.cm-selectionBackground, ::selection': { background: 'hsl(var(--brand)/0.2) !important' },
  '.cm-cursor': { borderLeftColor: 'hsl(var(--brand))' },
  '.tok-comment':     { color: 'var(--text-muted)', fontStyle: 'italic' },
  '.tok-string':      { color: 'hsl(var(--status-pass-text))' },
  '.tok-number':      { color: 'hsl(var(--status-info-text))' },
  '.tok-bool':        { color: 'hsl(var(--status-review-text))' },
  '.tok-keyword':     { color: 'hsl(var(--brand))' },
  '.tok-typeName':    { color: 'hsl(var(--status-info-text))' },
  '.tok-bracket':     { color: 'hsl(var(--brand))' },
  '.tok-punctuation': { color: 'var(--text-secondary)' },
}, { dark: true })

// Compartment lets us swap the theme extension without rebuilding the editor.
import { Compartment } from '@codemirror/state'
const themeCompartment = new Compartment()

function buildThemeExt(id: string): Extension {
  const t = EDITOR_THEMES[id]
  if (!t || id === 'ds-default') return [dsTheme, syntaxHighlighting(defaultHighlightStyle, { fallback: true })]
  return t.ext
}

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  value: string
  onChange: (value: string) => void
  minHeight?: number
  showError?: boolean
}

export function TomlEditor({ value, onChange, minHeight = 300, showError = true }: Props) {
  const error = useMemo(() => validateToml(value), [value])
  const containerRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)
  const onChangeRef = useRef(onChange)
  onChangeRef.current = onChange // eslint-disable-line react-hooks/refs

  const [themeId, setThemeId] = useState<string>(
    () => localStorage.getItem(THEME_KEY) ?? 'material-dark'
  )

  useEffect(() => {
    if (!containerRef.current) return

    const view = new EditorView({
      state: EditorState.create({
        doc: value,
        extensions: [
          history(),
          lineNumbers(),
          drawSelection(),
          highlightActiveLine(),
          StreamLanguage.define(toml),
          themeCompartment.of(buildThemeExt(themeId)),
          keymap.of([...defaultKeymap, ...historyKeymap]),
          EditorView.updateListener.of(update => {
            if (update.docChanged) onChangeRef.current(update.state.doc.toString())
          }),
          EditorView.lineWrapping,
        ],
      }),
      parent: containerRef.current,
    })

    viewRef.current = view
    return () => { view.destroy(); viewRef.current = null }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Sync external value changes
  useEffect(() => {
    const view = viewRef.current
    if (!view) return
    const current = view.state.doc.toString()
    if (current !== value) {
      view.dispatch({ changes: { from: 0, to: current.length, insert: value } })
    }
  }, [value])

  // Swap theme without rebuilding
  useEffect(() => {
    viewRef.current?.dispatch({
      effects: themeCompartment.reconfigure(buildThemeExt(themeId)),
    })
    localStorage.setItem(THEME_KEY, themeId)
  }, [themeId])

  const isDark = EDITOR_THEMES[themeId]?.dark ?? true

  return (
    <div className="toml-editor-wrap" style={{ background: isDark ? '#1e1e1e' : '#fff', minHeight }}>
      {/* Toolbar */}
      <div className="toml-editor-toolbar">
        <span className="toml-editor-label">TOML</span>
        <select
          value={themeId}
          onChange={e => setThemeId(e.target.value)}
          title="Editor colour scheme"
          className="toml-editor-theme-select"
        >
          {Object.entries(EDITOR_THEMES).map(([id, { label }]) => (
            <option key={id} value={id}>{label}</option>
          ))}
        </select>
      </div>

      <div ref={containerRef} className="toml-editor-content" style={{ minHeight: Math.max(0, minHeight - 28) }} />

      {showError && error && (
        <div className="toml-editor-error">
          {error}
        </div>
      )}
    </div>
  )
}
