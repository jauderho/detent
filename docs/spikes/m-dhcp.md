# Module spike: dhcp

Status: scaffold. Nothing has been run. Results come from the VM runs
(BUGFIX Track D, item 3, "D3"). PLAN Phase 8, task "verify on VM".

## Purpose

Show on a real VM that the `dhcp` module reads, validates, applies and rolls
back its real configuration files with the real service.

## Backends

dnsmasq (`dnsmasq.conf`, `dnsmasq.d/`), Kea DHCPv4 and DHCPv6 (JSON with comments).

## Include lines

A `conf-dir` line is allowed only with one of these values (owner decision
2026-10-15, BUGFIX D9), key `conf-dir` exactly. It gives the warning
`dhcp-stock-include`: the line stays in the file byte for byte, detent never
writes a new one, and it does not read or manage the directory. Every other
include or script line (`conf-file`, `conf-dir`, `include`, `includedir`,
`script`, `dhcp-script`, `dhcp-luascript`, `dhcp-scriptuser`) is an error, as
before.

| Value | Source |
|---|---|
| `/etc/dnsmasq.d,.rpmnew,.rpmsave,.rpmorig` | Fedora 44 stock `/etc/dnsmasq.conf` (dnsmasq 2.92-4.fc44), `fixtures/dhcp/distro/fedora-44.dnsmasq.conf` |
| `/etc/dnsmasq.d,.dpkg-dist,.dpkg-old,.dpkg-new` | Debian 13 (2.91-1+deb13u2) and Ubuntu 26.04 (2.92-1): `CONFIG_DIR` in `/etc/default/dnsmasq`, which the init script passes as `-7` (short for `conf-dir`); their `dnsmasq.conf` has no active `conf-dir` |

## External check

`dnsmasq --test -C <candidate>`, `kea-dhcp4 -t <candidate>`.

## Steps

Use a throwaway VM. Take a snapshot first. Do not edit the host's own
configuration outside detent.

1. Install the service and detent. Note the distribution and the service version.
2. Read the existing configuration with detent. Check that a plan with no change shows an empty diff.
3. Make one valid change. Check that the external check runs on the candidate and that apply writes the file.
4. Make one invalid change. Check that the external check refuses it and that nothing is written.
5. Check that the service reloads and keeps working after the apply.

## Result

Target distributions: Debian, Fedora, Ubuntu.

| Distribution | Service version | Read | Valid apply | Invalid refused | Service after apply | Notes |
|---|---|---|---|---|---|---|
| pending D3 | | | | | | |
