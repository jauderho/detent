import { describe, expect, it } from 'bun:test'
import {
  checkRows,
  isCoverableRow,
  listCoverableSrcFiles,
  parseCoverageTable,
} from '../coverage-check.ts'

describe('parseCoverageTable', () => {
  it('reads file rows and skips the header, separator, and summary', () => {
    const stdout = [
      'bun test v1.4.2 (744846f84)',
      '----------------------------------------------|---------|---------|',
      'File                                          | % Funcs | % Lines | Uncovered Line #s',
      '----------------------------------------------|---------|---------|',
      'All files                                     |   96.86 |   95.64 |',
      ' src/App.tsx                                  |  100.00 |  100.00 |',
      ' src/api/client.ts                            |   95.45 |   98.31 | 117',
      '----------------------------------------------|---------|---------|',
      '',
      ' 405 pass',
      ' 0 fail',
    ].join('\n')

    expect(parseCoverageTable(stdout)).toEqual([
      { file: 'src/App.tsx', linesPct: 100 },
      { file: 'src/api/client.ts', linesPct: 98.31 },
    ])
  })

  it('returns null when no table is present', () => {
    expect(parseCoverageTable('bun test v1.4.2\n\n 5 pass\n 0 fail\n')).toBeNull()
  })
})

describe('isCoverableRow', () => {
  it('accepts source rows and ignores fixtures, declarations, and tooling', () => {
    expect(isCoverableRow('src/App.tsx')).toBe(true)
    expect(isCoverableRow('src/forms/__fixtures__/hosts.schema.json?raw')).toBe(false)
    expect(isCoverableRow('src/test/matchers.d.ts')).toBe(false)
    expect(isCoverableRow('scripts/build-finish.ts')).toBe(false)
    expect(isCoverableRow('../locales/en-US/web.ftl?raw')).toBe(false)
  })
})

describe('listCoverableSrcFiles', () => {
  it('inventories source while skipping tests, fixtures, and declarations', async () => {
    const dir = await import('node:os').then((os) =>
      import('node:path').then((path) => path.join(os.tmpdir(), `coverage-check-${Date.now()}`)),
    )
    const { mkdirSync, writeFileSync } = await import('node:fs')
    mkdirSync(`${dir}/nested/__tests__`, { recursive: true })
    mkdirSync(`${dir}/nested/__fixtures__`, { recursive: true })
    writeFileSync(`${dir}/keep.ts`, 'export const x = 1\n')
    writeFileSync(`${dir}/nested/also.tsx`, 'export const y = 2\n')
    writeFileSync(`${dir}/nested/__tests__/keep.test.ts`, 'x\n')
    writeFileSync(`${dir}/nested/__fixtures__/f.json`, '{}\n')
    writeFileSync(`${dir}/types.d.ts`, 'export type T = number\n')

    // `src/`-rooted, sorted, and limited to coverable files.
    expect(listCoverableSrcFiles(dir)).toEqual(['src/keep.ts', 'src/nested/also.tsx'])

    const { rmSync } = await import('node:fs')
    rmSync(dir, { recursive: true })
  })
})

describe('checkRows', () => {
  it('flags shortfalls and files with no row, with no exclusions', () => {
    const rows = [
      { file: 'src/App.tsx', linesPct: 100 },
      { file: 'src/api/client.ts', linesPct: 98.31 },
      { file: 'src/components/ui/button.tsx', linesPct: 0 },
    ]

    expect(checkRows(rows, ['src/App.tsx', 'src/api/client.ts', 'src/api/auth.ts'])).toEqual({
      short: [
        { file: 'src/api/client.ts', linesPct: 98.31 },
        { file: 'src/components/ui/button.tsx', linesPct: 0 },
      ],
      missing: ['src/api/auth.ts'],
    })
  })

  it('passes a clean gate', () => {
    expect(checkRows([{ file: 'src/App.tsx', linesPct: 100 }], ['src/App.tsx'])).toEqual({
      short: [],
      missing: [],
    })
  })
})
