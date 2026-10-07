/**
 * What a `mounts` apply did with the fstab entries it added.
 */

import { describe, expect, it } from 'bun:test'
import { LocalizationProvider } from '@fluent/react'
import { render, screen } from '@testing-library/react'
import type { MountReportState, MountsReport } from '@/api/modules'
import { createLocalization } from '@/i18n'
import { MountResults, mountStateLabel } from '../MountResults'

const L10N = createLocalization(['en-US'])

function show(mounts: MountsReport) {
  return render(
    <LocalizationProvider l10n={L10N}>
      <MountResults mounts={mounts} />
    </LocalizationProvider>,
  )
}

describe('MountResults', () => {
  it('says that activation is off', () => {
    show({ activated: false, units: [], error: null })
    expect(screen.getByRole('status')).toHaveTextContent(/activate_new_entries/)
  })

  it('names the reason when no unit could start', () => {
    show({ activated: true, units: [], error: 'mount units need systemd' })
    expect(screen.getByRole('alert')).toHaveTextContent(/mount units need systemd/)
  })

  it('says that there was no new entry', () => {
    show({ activated: true, units: [] })
    expect(screen.getByRole('status')).toHaveTextContent(/no new fstab entry/)
  })

  it('lists each unit, and asks for attention when one did not mount', () => {
    show({
      activated: true,
      units: [
        { mountpoint: '/srv', unit: 'srv.mount', state: 'mounted', detail: '' },
        { mountpoint: '/nas', unit: 'nas.mount', state: 'failed', detail: 'mount boom' },
      ],
    })
    const banner = screen.getByRole('alert')
    expect(banner).toHaveTextContent('/srv')
    expect(banner).toHaveTextContent('/nas')
    expect(banner).toHaveTextContent('mount boom')
    expect(banner).toHaveTextContent(/failed/)
  })

  it('stays informational when every unit is mounted', () => {
    show({
      activated: true,
      units: [{ mountpoint: '/srv', unit: 'srv.mount', state: 'already_mounted', detail: '' }],
    })
    expect(screen.getByRole('status')).toHaveTextContent(/already mounted/)
  })
})

describe('mountStateLabel', () => {
  it('returns a localized word for every mount state', () => {
    const cases: { state: MountReportState; expected: string }[] = [
      { state: 'mounted', expected: 'mounted' },
      { state: 'already_mounted', expected: 'already mounted' },
      { state: 'pending', expected: 'still mounting' },
      { state: 'failed', expected: 'failed' },
      { state: 'protected', expected: 'refused: protected path' },
      { state: 'stopped', expected: 'unmounted' },
    ]
    for (const { state, expected } of cases) {
      expect(mountStateLabel(L10N, state)).toBe(expected)
    }
  })
})
