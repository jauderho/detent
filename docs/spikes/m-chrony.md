# Module spike: chrony

Status: scaffold. Nothing has been run. Results come from the VM runs
(BUGFIX Track D, item 3, "D3"). PLAN Phase 7, task "verify on VM".

## Purpose

Show on a real VM that the `chrony` module reads, validates, applies and rolls
back its real configuration files with the real service.

## Backends

`chrony.conf`, `sources.d/`, `conf.d/`.

`chrony.conf` is at `/etc/chrony/chrony.conf` on Debian and Ubuntu and at
`/etc/chrony.conf` on Fedora and Arch. The module manages the first of the two
that exists, `/etc/chrony/chrony.conf` when neither does (BUGFIX D8). When the
file is missing, `get` gives the warning `ops-target-missing`.

## Include lines

Only these stock lines are allowed (owner decision 2026-10-15, BUGFIX D9),
with exactly this key and value. Each gives the warning `chrony-stock-include`:
the line stays in the file byte for byte, and detent does not read or manage
the files it includes. Every other `include`, `includedir`, `confdir`,
`sourcedir` or `script` line is an error, as before.

| Line | Stock in |
|---|---|
| `sourcedir /run/chrony-dhcp` | Debian 13 (chrony 4.6.1-3+deb13u2), Ubuntu 26.04 (4.8-2ubuntu1), Fedora 44 (4.8-5.fc44) |
| `sourcedir /etc/chrony/sources.d` | Debian 13, Ubuntu 26.04 |
| `confdir /etc/chrony/conf.d` | Debian 13, Ubuntu 26.04 |

Arch (chrony 4.9-1) has no include line. The stock files are in
`fixtures/chrony/distro/`. The monitor still refuses a candidate that adds
such a line or changes one (`exec_deny.rs`).

## External check

`chronyd -p -f <candidate>`.

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
