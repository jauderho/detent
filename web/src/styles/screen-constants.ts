/**
 * AESTHETIC_CONTRACT.md §4 — the sanctioned screen-internal constants.
 *
 * These are the *only* hex values allowed outside the §3 token block. They are
 * deliberately not CSS variables: a screen never themes, so wiring it to a
 * themeable token would be a §12 anti-pattern ("theme a screen with the page").
 *
 * They live in a dependency-free module so that both `Screen.tsx` and
 * `scripts/contrast-check.ts` read the same values.
 */

/** LCD / readout background. */
export const SCREEN_BG = '#06121f'

/** LCD / readout hairline border. */
export const SCREEN_BORDER = '#0a3252'

/** Inner screen gray for unit suffixes and row names (§4 "inner text"). */
export const SCREEN_MUTED = '#9a9b95'
