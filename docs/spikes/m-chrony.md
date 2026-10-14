# Module spike: chrony

Status: scaffold. Nothing has been run. Results come from the VM runs
(BUGFIX Track D, item 3, "D3"). PLAN Phase 7, task "verify on VM".

## Purpose

Show on a real VM that the `chrony` module reads, validates, applies and rolls
back its real configuration files with the real service.

## Backends

`chrony.conf`, `sources.d/`, `conf.d/`.

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
