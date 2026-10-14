import { describe, expect, it } from 'bun:test'
import { render, screen } from '@testing-library/react'
import { SCREEN_BG } from '@/styles/screen-constants'
import { QrCode } from '../QrCode'

const URI = 'otpauth://totp/detent:alice?secret=JBSWY3DPEHPK3PXP&issuer=detent'

describe('QrCode', () => {
  it('draws the code as a named image with a quiet zone', () => {
    render(<QrCode value={URI} label="qr code" />)
    const image = screen.getByRole('img', { name: 'qr code' })
    const [width, height] = (image.getAttribute('viewBox') ?? '').split(' ').slice(2).map(Number)
    // The smallest code that holds this text at level M is version 4 (33
    // modules), plus four modules of margin on each side.
    expect(width).toBeGreaterThanOrEqual(33 + 8)
    expect(height).toBe(width)
    const path = image.querySelector('path')
    expect(path?.getAttribute('fill')).toBe(SCREEN_BG)
    // The finder pattern's top-left module sits just inside the quiet zone.
    expect(path?.getAttribute('d')?.startsWith('M4 4h1v1h-1z')).toBe(true)
  })

  it('draws a different code for different text', () => {
    const { container, rerender } = render(<QrCode value={URI} label="qr code" />)
    const first = container.querySelector('path')?.getAttribute('d')
    rerender(<QrCode value={`${URI}x`} label="qr code" />)
    expect(container.querySelector('path')?.getAttribute('d')).not.toBe(first)
  })
})
