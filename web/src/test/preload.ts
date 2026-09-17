/**
 * What `bun test` needs before a single test file is imported.
 *
 * Three things the runtime does not provide on its own:
 *
 * 1. **A DOM.** `bun test` runs in plain Bun, so `document` does not exist
 *    until happy-dom registers itself onto the global object. Older shims
 *    ship no `ResizeObserver`, which radix-ui's popper needs — see below.
 * 2. **Vite's asset imports.** `src/i18n/index.tsx` loads the Fluent bundle
 *    with `import source from '…/web.ftl?raw'`, and `src/main.tsx` pulls in
 *    font CSS and `index.css`, all Vite conventions Bun's module resolver
 *    knows nothing about. Loader plugins hand back the text (for `?raw`) or
 *    nothing (for `.css`, which only matters to a real browser's paint), so
 *    importing the entrypoint under test behaves like Vite would.
 * 3. **jest-dom's matchers**, which every component test asserts with.
 */
import { GlobalRegistrator } from '@happy-dom/global-registrator'
import { ensureResizeObserver } from './ensureResizeObserver'

GlobalRegistrator.register()

// happy-dom ships no ResizeObserver; radix-ui's popper (used by
// ui/tooltip.tsx) measures its content with one as soon as a tooltip opens.
ensureResizeObserver(globalThis as unknown as Record<string, unknown>)

// Registered before any test module is evaluated, so an `import … from
// '*.ftl?raw'` anywhere in the graph resolves through this rather than
// failing to resolve at all.
Bun.plugin({
  name: 'vite-raw-import',
  setup(build) {
    build.onLoad({ filter: /\?raw$/ }, async (args) => {
      const path = args.path.replace(/\?raw$/, '')
      const text = await Bun.file(path).text()
      return { contents: `export default ${JSON.stringify(text)}`, loader: 'js' }
    })
    // Stylesheets only matter to a browser's paint. The entrypoint imports
    // them for Vite; under test they resolve to nothing.
    build.onLoad({ filter: /\.css$/ }, () => ({ contents: 'export default {}', loader: 'js' }))
  },
})

const { expect, afterEach } = await import('bun:test')
const matchers = await import('@testing-library/jest-dom/matchers')
expect.extend(matchers.default ?? matchers)

const { cleanup } = await import('@testing-library/react')

afterEach(() => {
  cleanup()
})
