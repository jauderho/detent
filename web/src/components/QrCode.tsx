import { correction, generate } from 'lean-qr/nano'
import { SCREEN_BG, SCREEN_BORDER } from '@/styles/screen-constants'

/**
 * A QR code drawn as one SVG path.
 *
 * It is a screen element (AESTHETIC_CONTRACT.md §4): it does not follow the
 * theme. A scanner needs dark modules on a light field in both themes, so the
 * field is the always-lit `--screen-blue` and the modules are the screen
 * background constant (about 8:1), framed by the screen border.
 */

/** Modules of light margin round the code; ISO/IEC 18004 asks for four. */
const QUIET_ZONE = 4

/** Rendered size in CSS pixels, square. */
const SIZE_PX = 200

export type QrCodeProps = {
  /** The text to encode. */
  value: string
  /** What the image is, for assistive technology. */
  label: string
}

/** One `h1v1h-1z` square per dark module, offset by the quiet zone. */
function modulePath(value: string): { path: string; size: number } {
  const code = generate(value, { minCorrectionLevel: correction.M })
  let path = ''
  for (let y = 0; y < code.size; y += 1) {
    for (let x = 0; x < code.size; x += 1) {
      if (code.get(x, y)) path += `M${x + QUIET_ZONE} ${y + QUIET_ZONE}h1v1h-1z`
    }
  }
  return { path, size: code.size + QUIET_ZONE * 2 }
}

export function QrCode({ value, label }: QrCodeProps) {
  const { path, size } = modulePath(value)
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      width={SIZE_PX}
      height={SIZE_PX}
      shapeRendering="crispEdges"
      style={{ display: 'block', border: `1px solid ${SCREEN_BORDER}` }}
    >
      <rect width={size} height={size} fill="var(--screen-blue)" />
      <path d={path} fill={SCREEN_BG} />
    </svg>
  )
}
