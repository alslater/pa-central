import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({ useAuth: vi.fn() }))
vi.mock('@/hooks/useLiveAlerts', () => ({
  useLiveAlertsContext: () => ({
    count: 0, clear: vi.fn(), Toast: null, registerPendingOp: vi.fn(), getSessionEpoch: () => 0,
  }),
}))
vi.mock('@/lib/api', () => ({
  api: {
    systemSettings: { list: vi.fn(), update: vi.fn(), passwordResetReadiness: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import SystemSettings from '@/pages/SystemSettings'

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: { id: 1, email: 'a@example.com', display_name: 'A', role: 'admin' } } as any)
  vi.mocked(api.systemSettings.update).mockResolvedValue([])
  vi.mocked(api.systemSettings.passwordResetReadiness).mockResolvedValue({ ready: false, reasons: [] })
  vi.mocked(api.systemSettings.list).mockResolvedValue([])
})

describe('SystemSettings: fix plan budget', () => {
  it('renders the budget input and saves it', async () => {
    const user = userEvent.setup()
    render(<MemoryRouter><SystemSettings /></MemoryRouter>)
    const input = await screen.findByLabelText('Fix plan time budget (seconds)')
    await user.type(input, '600')
    await user.click(screen.getByRole('button', { name: /^save$/i }))
    const [updates] = vi.mocked(api.systemSettings.update).mock.calls[0]
    expect(updates).toEqual({ fix_plan_timeout_seconds: '600' })
  })
})
