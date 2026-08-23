import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { vi, beforeEach, describe, it, expect } from 'vitest'

vi.mock('@/hooks/useAuth', () => ({
  useAuth: vi.fn(),
}))

vi.mock('@/lib/api', () => ({
  api: {
    systemSettings: { list: vi.fn(), update: vi.fn() },
  },
}))

import { useAuth } from '@/hooks/useAuth'
import { api } from '@/lib/api'
import SystemSettings from '@/pages/SystemSettings'

const mockAdmin = { id: 1, email: 'admin@example.com', display_name: 'Admin', role: 'admin' as const }

function renderPage() {
  return render(<MemoryRouter><SystemSettings /></MemoryRouter>)
}

beforeEach(() => {
  vi.mocked(useAuth).mockReturnValue({ user: mockAdmin } as any)
  vi.mocked(api.systemSettings.update).mockResolvedValue([])
})

describe('SystemSettings — synthesized runtime defaults', () => {
  it('shows the effective default value and marks the field as unsaved', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'sla_high_days', value: '14', value_type: 'int', updated_at: null, updated_by_id: null, is_default: true },
    ] as any)

    renderPage()

    const input = await screen.findByLabelText(/SLA: High\/Critical \(days\).*using default/i)
    expect(input).toHaveValue(14)
  })

  it('does not mark a saved value as using a default', async () => {
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'sla_high_days', value: '21', value_type: 'int', updated_at: '2026-08-20T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()

    const input = await screen.findByLabelText(/^SLA: High\/Critical \(days\)$/i)
    expect(input).toHaveValue(21)
    expect(screen.queryByLabelText(/using default/i)).not.toBeInTheDocument()
  })

  it('does not persist an untouched default field when saving an unrelated setting', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'sla_high_days', value: '14', value_type: 'int', updated_at: null, updated_by_id: null, is_default: true },
      { key: 'smtp_host', value: 'old.smtp.example.com', value_type: 'string', updated_at: '2026-08-20T00:00:00Z', updated_by_id: 1, is_default: false },
    ] as any)

    renderPage()

    const smtpInput = await screen.findByLabelText(/SMTP Host/i)
    await user.clear(smtpInput)
    await user.type(smtpInput, 'new.smtp.example.com')
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(api.systemSettings.update).toHaveBeenCalledTimes(1)
    const [updates] = vi.mocked(api.systemSettings.update).mock.calls[0]
    expect(updates).toEqual({ smtp_host: 'new.smtp.example.com' })
    expect(updates).not.toHaveProperty('sla_high_days')
  })

  it('persists a default field once the admin explicitly edits it', async () => {
    const user = userEvent.setup()
    vi.mocked(api.systemSettings.list).mockResolvedValue([
      { key: 'sla_high_days', value: '14', value_type: 'int', updated_at: null, updated_by_id: null, is_default: true },
    ] as any)

    renderPage()

    const input = await screen.findByLabelText(/using default/i)
    await user.clear(input)
    await user.type(input, '21')
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(api.systemSettings.update).toHaveBeenCalledWith({ sla_high_days: '21' })
    // The "using default" marker must disappear once the field is edited,
    // even before the save round-trip completes.
    expect(screen.queryByLabelText(/using default/i)).not.toBeInTheDocument()
  })
})
