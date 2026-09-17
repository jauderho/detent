import { describe, expect, it } from 'bun:test'
import { jsonResponse, stubFetch } from '@/test/providers'
import { fetchBackups } from '../backups'
import { createApiClient } from '../client'

const BACKUP = {
  created_unix_s: 1_700_000_000,
  digest: 'a'.repeat(64),
  id: 0,
  len: 128,
  name: 'hosts.1700000000.bak',
  target: 0,
}

describe('fetchBackups', () => {
  it('addresses the module and returns the listing', async () => {
    const stub = stubFetch([jsonResponse([BACKUP])])
    const client = createApiClient({ fetch: stub.fetch })

    const result = await fetchBackups(client, 'hosts')

    expect(stub.calls[0]?.url).toBe('/api/v1/modules/hosts/backups')
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.data).toEqual([BACKUP])
  })

  // The module id reaches the URL, so it must be escaped rather than allowed
  // to add path segments of its own.
  it('escapes an id rather than letting it shape the path', async () => {
    const stub = stubFetch([jsonResponse([])])
    const client = createApiClient({ fetch: stub.fetch })

    await fetchBackups(client, '../../etc/passwd')

    expect(stub.calls[0]?.url).toBe('/api/v1/modules/..%2F..%2Fetc%2Fpasswd/backups')
  })
})
