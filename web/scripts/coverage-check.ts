#!/usr/bin/env bun
/**
 * Runs `bun test --coverage`, parses the per-file table, and fails unless
 * every coverable file under `src/` reads 100% lines. No exclusions: the
 * generated shadcn primitives (`ui/button.tsx`, `ui/tooltip.tsx`) were
 * deleted, `FieldFrame` uses Radix primitives directly.
 *
 * Everything coverable under `src/` is gated, including `src/test/`
 * (the harness itself) — a fallback branch in a helper is still a branch.
 * Rows that are not coverable TypeScript (`*.json?raw` fixtures,
 * `*.ftl?raw` locale bundles, `*.d.ts` declarations, anything outside
 * `src/`) are ignored, not counted as passes.
 *
 * The gate is fail-closed on inventory: every `.ts`/`.tsx` file under `src/`
 * (minus `__tests__`, `__fixtures__`, and `*.d.ts`) must appear in the
 * coverage table. A file with zero tests that the runner never loads
 * produces no row, which must fail — not pass by absence.
 *
 * Usage:
 *   bun run coverage:check              run the gate, exit non-zero on shortfall
 *   bun run coverage:check -- --verbose print every in-scope file and its line %
 *   bun run coverage:check -- --help    print this usage block
 *
 * CLI switches:
 *   --verbose, -v   Print the per-file line percentages the gate checked.
 *   --help, -h      Print usage and exit 0.
 *
 * Exit codes:
 *   0  every in-scope file is at 100% lines
 *   1  at least one in-scope file is below 100% lines, or has no coverage row
 *   2  the coverage run failed or its table could not be parsed
 */

import { spawnSync } from 'node:child_process'
import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const EXIT_OK = 0
const EXIT_SHORTFALL = 1
const EXIT_RUN_FAILED = 2

export type FileCoverage = { file: string; linesPct: number }

/**
 * Parses the per-file coverage table `bun test --coverage` prints.
 * Returns the data rows, or null when no table was found.
 */
export function parseCoverageTable(stdout: string): FileCoverage[] | null {
  const rows: FileCoverage[] = []
  let inTable = false
  for (const line of stdout.split('\n')) {
    if (/^File\s+\|\s+% Funcs/.test(line)) {
      inTable = true
      continue
    }
    if (!inTable) continue
    if (/^All files\s+\|/.test(line)) continue
    if (/^---/.test(line) || line.trim() === '') continue
    if (!line.includes('|')) {
      // The `N pass / M fail` summary ends the table.
      if (/pass|fail/.test(line)) break
      continue
    }
    const cells = line.split('|').map((cell) => cell.trim())
    const file = cells[0]
    const linesPctRaw = cells[2]
    if (file === undefined || file === '' || file === 'File') continue
    if (linesPctRaw === undefined) continue
    const linesPct = Number(linesPctRaw)
    if (!Number.isFinite(linesPct)) continue
    rows.push({ file, linesPct })
  }
  return rows.length > 0 ? rows : null
}

/** A coverage-table row carries TypeScript line data the gate can judge. */
export function isCoverableRow(file: string): boolean {
  if (!file.startsWith('src/')) return false
  if (!/\.tsx?$/.test(file)) return false
  if (file.endsWith('.d.ts')) return false
  return true
}
/**
 * Lists every coverable source file under `srcDir`, as `src/`-rooted paths.
 * Skips test files, fixtures, and declarations. Sorted for stable output.
 */
export function listCoverableSrcFiles(srcDir: string): string[] {
  const out: string[] = []
  const walk = (dir: string, rel: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      const relPath = rel === '' ? entry : `${rel}/${entry}`
      if (statSync(full).isDirectory()) {
        if (entry === '__tests__' || entry === '__fixtures__') continue
        walk(full, relPath)
      } else if (/\.tsx?$/.test(entry) && !entry.endsWith('.d.ts')) {
        out.push(`src/${relPath}`)
      }
    }
  }
  walk(srcDir, '')
  return out.sort()
}

export type CoverageVerdict = {
  short: FileCoverage[]
  missing: string[]
}

/** Applies the gate to parsed rows against the source inventory. */
export function checkRows(rows: FileCoverage[], inventory: string[]): CoverageVerdict {
  const seen: Record<string, true> = {}
  const short: FileCoverage[] = []
  for (const row of rows) {
    seen[row.file] = true
    if (!isCoverableRow(row.file)) continue
    if (row.linesPct < 100) short.push(row)
  }
  const missing: string[] = []
  for (const file of inventory) {
    if (!(file in seen)) missing.push(file)
  }
  return { short, missing }
}

function main(argv: readonly string[]): number {
  const verbose = argv.includes('--verbose') || argv.includes('-v')
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(
      [
        'coverage-check — enforce 100% lines on web/src (no exclusions).',
        '',
        'Usage: bun run coverage:check [-- --verbose] [-- --help]',
        '',
        '  --verbose, -v  print every in-scope file and its line %',
        '  --help, -h     print this message',
      ].join('\n'),
    )
    return EXIT_OK
  }

  const root = fileURLToPath(new URL('..', import.meta.url))
  const run = spawnSync('bun', ['test', '--coverage'], { cwd: root, encoding: 'utf8' })
  if (run.status !== 0) {
    console.error(`coverage-check: bun test --coverage failed:\n${run.stdout}${run.stderr}`)
    return EXIT_RUN_FAILED
  }

  const rows = parseCoverageTable(`${run.stdout}\n${run.stderr}`)
  if (rows === null) {
    console.error('coverage-check: could not parse the per-file coverage table.')
    return EXIT_RUN_FAILED
  }

  const inventory = listCoverableSrcFiles(join(root, 'src'))
  const { short, missing } = checkRows(rows, inventory)
  const scoped = rows.filter((row) => isCoverableRow(row.file))
  if (verbose || short.length > 0 || missing.length > 0) {
    for (const { file, linesPct } of scoped) {
      console.log(`coverage-check: ${file} → ${linesPct.toFixed(2)}% lines`)
    }
  }

  let failed = false
  if (short.length > 0) {
    failed = true
    console.error(
      `coverage-check: ${short.length} file(s) below 100% lines:\n` +
        short.map(({ file, linesPct }) => `  ${file} → ${linesPct.toFixed(2)}%`).join('\n'),
    )
  }
  if (missing.length > 0) {
    failed = true
    console.error(
      `coverage-check: ${missing.length} coverable file(s) with no coverage row:\n` +
        missing.map((file) => `  ${file}`).join('\n'),
    )
  }
  if (failed) return EXIT_SHORTFALL

  console.log(`coverage-check: OK — ${scoped.length} in-scope file(s) at 100% lines.`)
  return EXIT_OK
}

const entry = process.argv[1]
if (entry !== undefined && import.meta.url.startsWith('file:')) {
  if (fileURLToPath(import.meta.url) === entry) {
    process.exit(main(process.argv.slice(2)))
  }
}
