import { render } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { EditorView } from '@codemirror/view'
import { undo } from '@codemirror/commands'
import { TomlEditor } from '@/components/TomlEditor'

// TomlEditor's underlying EditorView instance persists across re-renders —
// switching Configs.tsx's `selected` template does not unmount/remount the
// editor, it just changes the `value` prop. Simulating a real keystroke (as
// opposed to re-rendering with a different `value`) requires dispatching
// directly against the live view, the same way a user's keypress would.
function typeInto(container: HTMLElement, text: string) {
  const view = (EditorView.findFromDOM(container.querySelector('.toml-editor-content')!) ?? null)
  if (!view) throw new Error('could not find EditorView in the rendered container')
  view.dispatch({ changes: { from: view.state.doc.length, insert: text } })
}

function viewFrom(container: HTMLElement): EditorView {
  const view = EditorView.findFromDOM(container.querySelector('.toml-editor-content')!)
  if (!view) throw new Error('could not find EditorView in the rendered container')
  return view
}

describe('TomlEditor — the value prop syncing the editor must never look like a user edit', () => {
  it('does not call onChange on mount when the initial value uses CRLF line endings', async () => {
    // CodeMirror's EditorState always normalizes \r\n to \n internally when
    // constructing the initial document. The sync effect used to compare
    // that normalized doc against the raw \r\n value, see them as
    // different, and dispatch a "correcting" change — firing onChange
    // before the user touched anything.
    const onChange = vi.fn()
    render(<TomlEditor value={'key = 1\r\nother = 2\r\n'} onChange={onChange} />)
    await new Promise(r => setTimeout(r, 30))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not call onChange on mount for lone-CR (classic Mac) line endings either', async () => {
    const onChange = vi.fn()
    render(<TomlEditor value={'key = 1\rother = 2\r'} onChange={onChange} />)
    await new Promise(r => setTimeout(r, 30))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not call onChange when the value prop switches to different external content', async () => {
    // Regression test for the actual reported bug: switching Configs.tsx's
    // selected template re-renders TomlEditor with a new `value`, but the
    // *same* EditorView instance stays mounted throughout. The sync effect
    // dispatches a change to make the visible doc match the new value —
    // and without tagging that dispatch as an external sync, it fired
    // onChange exactly like a real edit would, marking the newly-selected
    // template dirty despite the user never touching it.
    const onChange = vi.fn()
    const { rerender } = render(<TomlEditor value="template-a" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    rerender(<TomlEditor value="template-b" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not call onChange when switching to another template and back', async () => {
    // The exact user-reported reproduction: save (clean), switch away,
    // switch back — "Unsaved" must not reappear with no edit in between.
    const onChange = vi.fn()
    const { rerender } = render(<TomlEditor value="template-a" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))

    rerender(<TomlEditor value="template-b" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    rerender(<TomlEditor value="template-a" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not re-sync (or call onChange) when the value prop is re-passed unchanged', async () => {
    const onChange = vi.fn()
    const { rerender } = render(<TomlEditor value={'key = 1\r\n'} onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    rerender(<TomlEditor value={'key = 1\r\n'} onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not let Ctrl+Z after a template switch restore the previous template\'s content', async () => {
    // P1 regression: view.dispatch() in the sync effect suppresses onChange
    // but by itself does nothing to the undo history — the replacement is
    // still a recorded, undoable transaction. Without resetting history on
    // an external sync, switching from template-a to template-b and
    // pressing Ctrl+Z (or calling undo()) restores template-a's TOML into
    // the buffer now labelled template-b, silently marks it dirty, and lets
    // the user save the wrong template's content over it.
    const onChange = vi.fn()
    const { container, rerender } = render(<TomlEditor value="template-a-content" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))

    rerender(<TomlEditor value="template-b-content" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    const view = viewFrom(container)
    undo(view)
    await new Promise(r => setTimeout(r, 20))

    expect(view.state.doc.toString()).toBe('template-b-content')
    expect(onChange).not.toHaveBeenCalled()
  })

  it('does not let Ctrl+Z apply a previous template\'s edits after remounting via key for an identity switch with identical content', async () => {
    // P1 regression: the sync effect only resets state (including undo
    // history — see the fix above) when the *document text* differs from
    // the previous value. Two distinct templates can hold identical TOML
    // (both freshly created from the same boilerplate, or both blank), so
    // switching between them changes identity without changing text — the
    // effect's `current !== normalizedValue` guard is false and no reset
    // happens at all. TomlEditor has no notion of "template identity" by
    // itself; the caller (Configs.tsx) supplies it as a React `key`, which
    // remounts the component — and with it, the EditorView and its history
    // — regardless of whether the content happens to match.
    const onChange = vi.fn()
    const { container, rerender } = render(
      <TomlEditor key="template-a" value="shared-content" onChange={onChange} />
    )
    await new Promise(r => setTimeout(r, 20))

    typeInto(container, '\nedited-only-in-a')
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    // Switch to a different template that happens to hold the exact same
    // text template-a started with — a different `key` remounts.
    rerender(<TomlEditor key="template-b" value="shared-content" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    const view = viewFrom(container)
    undo(view)
    await new Promise(r => setTimeout(r, 20))

    expect(view.state.doc.toString()).toBe('shared-content')
    expect(onChange).not.toHaveBeenCalled()
  })

  it('still calls onChange for an actual user keystroke', async () => {
    // The fix must not make the editor mute entirely — a genuine edit
    // (dispatched directly against the live view, as a keypress would)
    // must still be reported.
    const onChange = vi.fn()
    const { container } = render(<TomlEditor value="key = 1" onChange={onChange} />)
    await new Promise(r => setTimeout(r, 20))
    onChange.mockClear()

    typeInto(container, '\nother = 2')
    await new Promise(r => setTimeout(r, 20))

    expect(onChange).toHaveBeenCalledTimes(1)
    expect(onChange).toHaveBeenCalledWith('key = 1\nother = 2')
  })
})
