/**
 * What `bun test` needs before a single test file is imported.
 *
 * Three things the runtime does not provide on its own:
 *
 * 1. **A DOM.** `bun test` runs in plain Bun, so `document` does not exist
 *    until happy-dom registers itself onto the global object.
 * 2. **Vite's `?raw` imports.** `src/i18n/index.tsx` loads the Fluent bundle
 *    with `import source from '…/web.ftl?raw'`, which is a Vite convention
 *    Bun's module resolver knows nothing about. A loader plugin reads the file
 *    and hands back its text, exactly as Vite would.
 * 3. **jest-dom's matchers**, which every component test asserts with.
 */

import { GlobalRegistrator } from '@happy-dom/global-registrator'

GlobalRegistrator.register()

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
  },
})

const { expect, afterEach } = await import('bun:test')
const matchers = await import('@testing-library/jest-dom/matchers')
expect.extend(matchers.default ?? matchers)

const { cleanup } = await import('@testing-library/react')

// happy-dom ships no ResizeObserver; radix-ui's popper (used by
// ui/tooltip.tsx) measures its content with one as soon as a tooltip opens.
if (!('ResizeObserver' in globalThis)) {
  globalThis.ResizeObserver = class {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  } as unknown as typeof ResizeObserver
}

afterEach(() => {
  cleanup()
})
