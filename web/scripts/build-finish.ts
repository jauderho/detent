#!/usr/bin/env bun
/**
 * build-finish — finish a production build so the Rust binary can serve it.
 *
 * `vite build` minifies JS (terser) and CSS (lightningcss), but two things it
 * does not do are load-bearing here:
 *
 *   1. `crates/detent-web/src/spa.rs` **never compresses at request time**. It
 *      serves a pre-compressed `.br` / `.gz` sibling if one was embedded, and
 *      falls back to identity otherwise. Without this step every asset ships
 *      uncompressed over the wire, silently. Brotli only by default — see
 *      `compressOne` for why a gzip sibling would earn nothing here.
 *   2. The Content-Security-Policy in `crates/detent-web/src/headers.rs` pins
 *      the SHA-256 of the inline theme script by value. Rust tests check that
 *      constant against `web/src/theme-init.js` and against the *source*
 *      `index.html` — but the file that actually ships is `dist/index.html`,
 *      which no Rust test sees. If anything in the build perturbs that script
 *      by even one byte, the shipped page violates its own CSP and the theme
 *      never applies. This step re-derives the digest from the built HTML and
 *      fails the build if it has moved.
 *
 * It also drops the legacy `woff` font fallback (see `dropLegacyWoff`) and
 * recreates `dist/.gitkeep`, which `vite build` deletes when it empties the
 * output directory and which the Rust `ui` feature needs to exist.
 *
 * Usage:
 *   bun run build:finish                 compress dist/ and verify the CSP hash
 *   bun run build:finish -- --dryrun     report what would be written, write nothing
 *   bun run build:finish -- --verbose    per-file sizes and ratios
 *   bun run build:finish -- --help       print this usage block
 *
 * CLI switches:
 *   --dryrun        Do everything except write. The CSP hash check still runs,
 *                   because it only reads.
 *   --gzip          Also emit `.gz` siblings. Off by default: brotli already
 *                   covers every browser, and each sibling is permanent bytes
 *                   in the binary. For a gzip-only reverse proxy.
 *   --keep-woff     Keep the legacy `woff` font fallback.
 *   --verbose, -v   Print every file with its raw, brotli and gzip sizes.
 *   --help, -h      Print usage and exit 0.
 *
 * Exit codes:
 *   0  dist/ compressed and the CSP hash still matches
 *   1  the inline script no longer hashes to the pinned CSP value
 *   2  dist/ or the Rust constant could not be read
 */

import { createHash } from 'node:crypto'
import { readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { brotliCompressSync, constants, gzipSync } from 'node:zlib'

const EXIT_OK = 0
const EXIT_CSP_MISMATCH = 1
const EXIT_UNREADABLE = 2

/** Extensions worth pre-compressing. Images and fonts are already compressed. */
const COMPRESSIBLE = /\.(js|mjs|css|html|json|svg|map|txt|ftl)$/

/**
 * Below this, a compressed sibling costs more embedded bytes than it saves on
 * the wire — and every embedded byte is a byte of the binary.
 */
const MIN_BYTES_TO_COMPRESS = 256

/** Only keep a sibling that is actually smaller than the original. */
const MAX_USEFUL_RATIO = 0.95

/**
 * Resolved lazily, not at module scope: under the vitest runner
 * `import.meta.url` is not a `file:` URL, and `fileURLToPath` would throw on
 * import — taking the pure helpers below down with it. Same reason as
 * `contrast-check.ts`'s `tokensPath()`.
 */
function webRoot(): string {
  return fileURLToPath(new URL('..', import.meta.url))
}
function distDir(): string {
  return join(webRoot(), 'dist')
}
function headersRs(): string {
  return join(webRoot(), '..', 'crates', 'detent-web', 'src', 'headers.rs')
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else out.push(full)
  }
  return out
}

/** Base64 SHA-256, the form a CSP `'sha256-…'` source expression uses. */
export function cspDigest(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('base64')
}

/** The value of `THEME_SCRIPT_SHA256` in headers.rs. */
export function pinnedCspHash(rustSource: string): string | null {
  const match = /THEME_SCRIPT_SHA256:\s*&str\s*=\s*"([^"]+)"/.exec(rustSource)
  return match?.[1] ?? null
}

/**
 * The text content of the first inline `<script>` (one with no `src`).
 *
 * A CSP `'sha256-…'` covers the element's text content exactly, whitespace and
 * indentation included, so this deliberately does not trim.
 */
export function inlineScript(html: string): string | null {
  const match = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/.exec(html)
  return match?.[1] ?? null
}

/**
 * Strips the legacy `woff` fallback from every `@font-face` that also offers
 * `woff2`, and reports the files that become unreferenced.
 *
 * `@fontsource` ships both formats and vite emits both. `woff2` has been
 * supported by every browser since 2016, and `build.target` here is `es2023`,
 * so no browser that can run this bundle would ever reach the fallback — it is
 * pure embedded weight in the binary.
 *
 * The pattern requires the leading comma, so a face offering *only* `woff` is
 * left alone rather than stripped down to nothing.
 */
export function dropLegacyWoff(css: string): { css: string; dropped: string[] } {
  const dropped: string[] = []
  const stripped = css.replace(
    /,url\(([^)]*\.woff)\)\s*format\("woff"\)/g,
    (_match, url: string) => {
      dropped.push(url.replace(/^.*\//, ''))
      return ''
    },
  )
  return { css: stripped, dropped }
}

type Report = { path: string; raw: number; br: number | null; gz: number | null }

/**
 * Writes the pre-compressed siblings for one file.
 *
 * **Brotli only, by default.** Every sibling is embedded in the binary, so a
 * second encoding is not free the way it is on a CDN — it is permanent bytes
 * in `detent`. Brotli at quality 11 beats gzip -9 on this bundle and has been
 * supported by every browser since 2016, which is a strictly wider set than
 * the `es2023` bundle itself runs on. A gzip sibling would therefore serve no
 * browser that brotli does not already serve, and any non-browser client that
 * sends no `Accept-Encoding` still gets the identity file. `--gzip` is there
 * for an operator fronting detent with a proxy that only speaks gzip.
 *
 * zstd is deliberately not produced: `spa.rs` does not negotiate it, Safari
 * does not accept it, and its ratio on text is not better than brotli's — so
 * it would cost embedded bytes to serve a subset of what brotli already
 * covers.
 */
function compressOne(file: string, dryrun: boolean, gzip: boolean): Report {
  const bytes = readFileSync(file)
  const report: Report = { path: relative(distDir(), file), raw: bytes.length, br: null, gz: null }
  if (bytes.length < MIN_BYTES_TO_COMPRESS) return report

  const br = brotliCompressSync(bytes, {
    params: {
      [constants.BROTLI_PARAM_QUALITY]: constants.BROTLI_MAX_QUALITY,
      [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length,
    },
  })
  if (br.length < bytes.length * MAX_USEFUL_RATIO) {
    report.br = br.length
    if (!dryrun) writeFileSync(`${file}.br`, br)
  }

  if (gzip) {
    const gz = gzipSync(bytes, { level: 9 })
    if (gz.length < bytes.length * MAX_USEFUL_RATIO) {
      report.gz = gz.length
      if (!dryrun) writeFileSync(`${file}.gz`, gz)
    }
  }
  return report
}

function main(argv: readonly string[]): number {
  const verbose = argv.includes('--verbose') || argv.includes('-v')
  const dryrun = argv.includes('--dryrun')
  const gzip = argv.includes('--gzip')
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(
      [
        'build-finish — compress dist/ and verify the pinned CSP hash.',
        '',
        'Usage: bun run build:finish [-- --dryrun] [-- --verbose] [-- --help]',
        '',
        '  --dryrun       report without writing anything',
        '  --gzip         also emit .gz siblings (brotli alone covers every',
        '                 browser; use this only behind a gzip-only proxy)',
        '  --keep-woff    keep the legacy woff font fallback (woff2 is enough',
        '                 for every browser this bundle runs on)',
        '  --verbose, -v  per-file raw/brotli/gzip sizes',
        '  --help, -h     print this message',
      ].join('\n'),
    )
    return EXIT_OK
  }

  let files: string[]
  try {
    files = walk(distDir()).filter((f) => !/\.(br|gz)$/.test(f))
  } catch (error) {
    console.error(
      `build-finish: cannot read ${distDir()} — run \`bun run build\` first (${String(error)})`,
    )
    return EXIT_UNREADABLE
  }

  // ── the CSP hash the shipped page must still satisfy ──────────────────────
  const builtHtml = join(distDir(), 'index.html')
  let pinned: string | null
  let built: string
  try {
    pinned = pinnedCspHash(readFileSync(headersRs(), 'utf8'))
    built = readFileSync(builtHtml, 'utf8')
  } catch (error) {
    console.error(`build-finish: cannot read the CSP inputs (${String(error)})`)
    return EXIT_UNREADABLE
  }
  if (pinned === null) {
    console.error(`build-finish: could not find THEME_SCRIPT_SHA256 in ${headersRs()}`)
    return EXIT_UNREADABLE
  }
  const script = inlineScript(built)
  if (script === null) {
    console.error(
      'build-finish: dist/index.html has no inline <script>. The theme would flash on load, ' +
        'and the CSP hash in headers.rs now pins nothing.',
    )
    return EXIT_CSP_MISMATCH
  }
  const actual = cspDigest(script)
  if (actual !== pinned) {
    console.error(
      `build-finish: the built inline script hashes to "${actual}" but the CSP in\n` +
        `  crates/detent-web/src/headers.rs pins "${pinned}".\n` +
        '  The shipped page would violate its own CSP and load unthemed.\n' +
        '  Something in the build perturbed the script text; a CSP sha256- source covers\n' +
        '  the element content byte for byte, indentation included.',
    )
    return EXIT_CSP_MISMATCH
  }
  console.log(`build-finish: CSP hash OK — inline theme script matches the pinned sha256.`)

  // ── drop the legacy woff fallback ─────────────────────────────────────────
  let woffFreed = 0
  if (!argv.includes('--keep-woff')) {
    const orphaned = new Set<string>()
    for (const file of files.filter((f) => f.endsWith('.css'))) {
      const { css, dropped } = dropLegacyWoff(readFileSync(file, 'utf8'))
      for (const name of dropped) orphaned.add(name)
      if (dropped.length > 0 && !dryrun) writeFileSync(file, css)
    }
    for (const name of orphaned) {
      const path = join(distDir(), 'assets', name)
      try {
        woffFreed += statSync(path).size
        if (!dryrun) rmSync(path)
      } catch {
        // Already gone, or emitted somewhere this build does not expect. The
        // CSS reference is stripped either way, which is the part that matters.
      }
    }
    if (orphaned.size > 0) {
      console.log(
        `build-finish: dropped ${orphaned.size.toString()} legacy .woff file(s), ` +
          `${woffFreed} B — woff2 covers every browser this bundle targets.`,
      )
    }
  }

  // `dist/` is tracked only by this placeholder, and `vite build` empties the
  // directory, so recreate it or the next `--all-features` cargo build fails
  // on a missing rust-embed folder.
  if (!dryrun) writeFileSync(join(distDir(), '.gitkeep'), '')

  // ── pre-compressed siblings ───────────────────────────────────────────────
  const compressible = files.filter((f) => COMPRESSIBLE.test(f))
  const reports = compressible.map((f) => compressOne(f, dryrun, gzip))
  let raw = 0
  let br = 0
  for (const report of reports) {
    raw += report.raw
    br += report.br ?? report.raw
    if (verbose) {
      const brText = report.br === null ? '—' : String(report.br)
      const gzText = report.gz === null ? '—' : String(report.gz)
      console.log(`  ${report.path.padEnd(44)} raw=${report.raw} br=${brText} gz=${gzText}`)
    }
  }
  const saved = raw - br
  const pct = raw === 0 ? 0 : (100 * saved) / raw
  console.log(
    `build-finish: ${dryrun ? 'would compress' : 'compressed'} ${reports.length.toString()} file(s); ` +
      `${raw} B raw → ${br} B brotli on the wire (${pct.toFixed(1)}% smaller).`,
  )
  return EXIT_OK
}

// Importable from the test suite without running.
const entry = process.argv[1]
if (entry !== undefined && import.meta.url.startsWith('file:')) {
  if (fileURLToPath(import.meta.url) === entry) {
    process.exit(main(process.argv.slice(2)))
  }
}
