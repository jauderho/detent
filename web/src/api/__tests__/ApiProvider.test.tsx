/**
 * Wiring the API client and React Query client into context.
 */

import { describe, expect, it } from 'bun:test'
import { render, screen } from '@testing-library/react'
import { ApiProvider, useApiClient } from '../ApiProvider'

function ClientProbe() {
  const client = useApiClient()
  return <div data-testid="hasToken">{client.hasCsrfToken() ? 'yes' : 'no'}</div>
}

describe('ApiProvider', () => {
  it('builds its own client and query client when none are injected', () => {
    render(
      <ApiProvider>
        <ClientProbe />
      </ApiProvider>,
    )

    expect(screen.getByTestId('hasToken')).toHaveTextContent('no')
  })

  it('throws when useApiClient is called outside the provider', () => {
    expect(() => render(<ClientProbe />)).toThrow('useApiClient must be used inside <ApiProvider>')
  })
})
