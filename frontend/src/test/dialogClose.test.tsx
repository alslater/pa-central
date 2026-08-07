/**
 * Modal / Drawer close behaviour.
 *
 * Both mirror the `onClose` prop into a ref so `stableClose` keeps a constant
 * identity for useDialogAccessibility. The ref is written in an effect rather
 * than during render, so these pin the two things that could break:
 *   - close still fires (Escape and backdrop click)
 *   - a *replaced* onClose prop is the one invoked, not the mount-time one
 */
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi, describe, it, expect, beforeEach } from 'vitest'

import { Modal, Drawer } from '@/components/ui'

const DIALOGS = [
  ['Modal', Modal],
  ['Drawer', Drawer],
] as const

describe.each(DIALOGS)('%s — close behaviour', (name, Dialog) => {
  beforeEach(() => { vi.clearAllMocks() })

  it('calls onClose on Escape', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<Dialog title={`${name} title`} onClose={onClose}><p>body</p></Dialog>)
    await user.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onClose when the backdrop is clicked', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<Dialog title={`${name} title`} onClose={onClose}><p>body</p></Dialog>)
    // The backdrop is the presentation-role wrapper around the dialog panel.
    const backdrop = screen.getByRole('presentation')
    await user.click(backdrop)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('does not close when the panel itself is clicked', async () => {
    const user = userEvent.setup()
    const onClose = vi.fn()
    render(<Dialog title={`${name} title`} onClose={onClose}><p>body</p></Dialog>)
    await user.click(screen.getByText('body'))
    expect(onClose).not.toHaveBeenCalled()
  })

  it('invokes the latest onClose after the prop changes', async () => {
    const user = userEvent.setup()
    const first = vi.fn()
    const second = vi.fn()
    const { rerender } = render(
      <Dialog title={`${name} title`} onClose={first}><p>body</p></Dialog>,
    )
    // Re-render with a new callback: the ref must have been re-synced, or the
    // stale mount-time callback fires instead.
    rerender(<Dialog title={`${name} title`} onClose={second}><p>body</p></Dialog>)
    await user.keyboard('{Escape}')
    expect(second).toHaveBeenCalledTimes(1)
    expect(first).not.toHaveBeenCalled()
  })
})
