# Spike: dns-01 issuance against Pebble + challtestsrv

Phase 6, Task 1 — proves the `detent-acme` seam (`DnsProvider` /
`HookProvider`, atomic challenge writes) end-to-end with a real RFC 8555
server. Driver: `crates/detent-acme/src/order.rs` on `instant-acme 0.8.5`;
live test: `crates/detent-acme/tests/pebble_live.rs`.

## Dependencies

- `instant-acme = "=0.8.5"` (pinned exact). Defaults give `aws-lc-rs` +
  `hyper-rustls`; `rcgen` added for CSR generation. `cargo tree
  -p detent-acme -i ring` is empty — single crypto stack, no `ring`
  duplication, no cfg gate needed.
- No hickory, no new DNS dependency. Propagation check is a `dig` retry loop
  (test-side); the library itself stays std-only and tokio-free (tokio only
  as a dev-dependency to block on the async flow in the live test).
- Cooldown §6.4: instant-acme 0.8.5 published 2026-02-24 — CLEAR.

## Pebble + challtestsrv stack

```sh
# Pebble, validating dns-01 through challtestsrv (custom resolver via flag;
# the config file is mounted only to keep 0.0.0.0 listeners for containers)
cat > /tmp/detent-pebble/pebble-config.json <<'EOF'
{ "pebble": { "listenAddress": "0.0.0.0:14000",
              "managementListenAddress": "0.0.0.0:15000",
              "certificate": "test/certs/localhost/cert.pem",
              "privateKey": "test/certs/localhost/key.pem",
              "httpPort": 5002, "tlsPort": 5001,
              "domainBlocklist": ["blocked-domain.example"] } }
EOF
docker run -d --name pebble -p 14000:14000 -p 15000:15000 \
  -v /tmp/detent-pebble/pebble-config.json:/test/config/pebble-config.json \
  ghcr.io/letsencrypt/pebble:latest \
  -config /test/config/pebble-config.json \
  -dnsserver host.docker.internal:8053

# challtestsrv: DNS server on :8053 (TCP+UDP), management API on :8055
docker run -d --name challtestsrv \
  -p 8053:8053 -p 8053:8053/udp -p 8055:8055 \
  ghcr.io/letsencrypt/pebble-challtestsrv:latest \
  -defaultIPv4 "" -defaultIPv6 "" -dnsserver ":8053" \
  -http01 ":5002" -https01 ":5003" -tlsalpn01 ":5001" -management ":8055"

# Pebble's root CA for the Rust client (rustls must trust it)
docker cp pebble:/test/certs/pebble.minica.pem /tmp/detent-pebble/pebble.minica.pem
```

Gotchas (both cost a container restart during the spike):

- `ghcr.io/letsencrypt/pebble:latest` has no shell (`FROM scratch`); inspect
  it via `docker run ... -help` only.
- Pebble takes the DNS resolver as the `-dnsserver` CLI flag; a
  `DNSResolver` key in the config JSON is ignored (it logs "Using system DNS
  resolver" and TXT lookups go out to the real Internet).
- The challtestsrv DNS flag is `-dnsserver`, not `-dns01`.
- Pebble validates dns-01 by querying `host.docker.internal:8053` — Docker
  Desktop routes this to the host, where the challtestsrv port map lands.

## Wiring

- `HookProvider.present` writes `<state_dir>/_acme-challenge.<domain>.txt`
  (0600 file, 0700 dir, atomic temp+rename). challtestsrv cannot read files,
  so the live test bridges: it reads the hook file back and POSTs
  `{"host":"_acme-challenge.le.wtf.", "value":"<digest>"}` to the
  management API (`/set-txt`). The file is the hook contract; challtestsrv
  is the external responder. After the order resolves the test withdraws:
  hook files deleted, `/clear-txt` posted.
- Propagation: `dig @127.0.0.1 -p 8053 +short <fqdn> TXT` in a retry loop
  until the digest matches — plain UDP confirmation, no DNS crate.

## Transcript (2026-09-17, pebble3 / challtestsrv2)

```
$ PEBBLE_URL=https://localhost:14000/dir \
  PEBBLE_CA=/tmp/detent-pebble/pebble.minica.pem \
  CHALLTESTSRV=http://localhost:8055 \
  cargo test -p detent-acme --test pebble_live -- --ignored --nocapture

account: https://localhost:14000/my-account/5babd453b05fd5d
order:   https://localhost:14000/my-order/wJOvtVdKiR4YBFu-NfK-m88vhwjtUxkfbt9ez8G8Mzw
challenges presented and marked ready
status:  Ready
chain:   2 PEM block(s)
done:    order valid, certificate downloaded

test pebble_dns01_issuance ... ok
```

challtestsrv log, the digest `HookProvider` published (read back from the
0600 hook file, then fed to challtestsrv):

```
Added TXT response for Host "_acme-challenge.le.wtf" -
    Value "DDgc1cdXdKy7gQ8m-r719n-8qzpnWkRmEvXCsEvwPxc"
```

Certificate (leaf of the 2-cert chain):

```
serial             48B71D6639B3E30D
sha256 fingerprint 33:E2:E9:7F:4B:0B:77:59:87:5C:94:23:55:C0:F1:F5:
                   61:FE:89:2E:6A:1A:CC:A3:08:CA:1C:F2:BE:9A:10:0D
SAN                DNS:le.wtf
notBefore          Sep 17 10:21:49 2026 GMT
notAfter           Sep 23 10:21:48 2026 GMT   (6 days, Pebble default)
```

Test assertions: chain PEM decodes to DER (SEQUENCE tag), the requested
domain's raw bytes appear in the leaf DER (SAN dNSName is IA5String, so the
domain is embedded verbatim). Chosen over adding a full X.509 parser
dependency for a spike assertion.

## What failed on the way

1. Wrong flags first try (`-strict false`, `-dns01`) — see gotchas above.
2. First issuance attempt hit
   `error:unauthorized: lookup _acme-challenge.le.wtf on 0.250.250.200:53:
   no such host` — Pebble was resolving through the system resolver, not
   challtestsrv; fixed by the `-dnsserver` flag.
3. challtestsrv logs a benign `open : no such file or directory` at startup
   (empty default-response database); it serves fine.

## ARI

Deferred. `instant-acme` exposes it (`NewOrder::replaces` +
`Account::renewal_info`, needs the `time` feature; Pebble serves
`/renewalInfo`), but the spike's scope is first issuance: there is no
previously issued certificate to replace yet. The renewal scheduler (Phase 6
Task 2+) will produce the serial/AKI needed for `CertificateIdentifier`; ARI
renewal should be exercised then, against the same Pebble stack with a
replaces-order.

## API notes

- `detent-acme` stays std-only in its own deps: the order flow is async and
  the caller drives it with its own runtime. No sleeps in the library —
  `wait_ready` / `finalize` take an `instant_acme::RetryPolicy` that owns
  timing (caller-owned retry loop).
- Account credentials are cached at `<state>/account.json` (0600, atomic
  temp+rename); the live test deletes it per run for a fresh account.
- `AcmeError` gained `Acme(#[from] instant_acme::Error)`,
  `NoDns01Challenge`, `Credentials(String)`, `InvalidOrder(OrderStatus)`.
