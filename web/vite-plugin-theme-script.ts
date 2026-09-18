import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import type { Plugin } from 'vite'

/** The marker in index.html that the theme `<script>` replaces. */
const PLACEHOLDER = '<!--THEME_INIT_SCRIPT-->'

/**
 * Injects `src/theme-init.js` into index.html as an inline `<script>`.
 *
 * The script must run before first paint, so it cannot be a module import —
 * and its text must be the source file byte for byte, because the CSP in
 * `detent-web/src/headers.rs` pins a `sha256-` of it and a CSP hash covers the
 * element's text content exactly, indentation included. Injecting it here
 * instead of pasting it into index.html is what keeps the two from drifting;
 * `scripts/build-finish.ts` re-hashes the built page and fails the build if
 * they ever do.
 *
 * The placeholder is a bare HTML comment rather than an empty `<script>` so
 * that index.html stays parseable — biome lints it as HTML, and a `<script>`
 * body of `<!--…-->` is not valid JavaScript.
 *
 * Applies in dev as well as build: with `apply: 'build'` the placeholder
 * survives into the dev page, where `<!--…-->` is a legacy JS line comment, so
 * the theme silently never initialises and every dev reload flashes unthemed.
 */
export function themeScriptPlugin(): Plugin {
  let themeScript = ''

  return {
    name: 'detent:theme-script',
    configResolved() {
      themeScript = readFileSync(resolve(__dirname, 'src/theme-init.js'), 'utf8')
    },
    transformIndexHtml(html: string) {
      if (!themeScript) {
        throw new Error('themeScriptPlugin: theme-init.js not loaded')
      }
      if (!html.includes(PLACEHOLDER)) {
        throw new Error(`themeScriptPlugin: ${PLACEHOLDER} missing from index.html`)
      }
      // A function replacement: `$&` and friends are literal in the script.
      return html.replace(PLACEHOLDER, () => `<script>${themeScript}</script>`)
    },
  }
}
