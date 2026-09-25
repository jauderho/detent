# Disk hygiene for this repository. The logic lives in scripts/clean.sh.
#
#   make clean       Remove large, rarely reused output (incremental caches,
#                    coverage, release/cross builds, fuzz builds, test reports,
#                    stale debug files). Keeps the warm debug build and
#                    web/node_modules, so the next build is still fast.
#   make realclean   Remove every ignored file except .sops/ and .mcp.json*,
#                    plus the generated fuzz corpus: the tree as if just
#                    cloned. Tracked files and your own untracked files stay.
#   make du          Show what takes the space.
#
# Options: DRYRUN=1 prints what would be removed; VERBOSE=1 lists each path;
# STALE_DAYS=N changes the stale-file age for `make clean` (default 2).

SHELL := /usr/bin/env bash
CLEAN := scripts/clean.sh
CLEAN_FLAGS := $(if $(DRYRUN),--dryrun) $(if $(VERBOSE),--verbose)

.PHONY: help clean realclean du

help:
	@sed -n '3,14p' Makefile | sed 's/^# \{0,1\}//'

clean:
	@$(CLEAN) $(CLEAN_FLAGS)

realclean:
	@$(CLEAN) --real $(CLEAN_FLAGS)

du:
	@du -sh target/* fuzz/target web/node_modules web/dist 2>/dev/null | sort -h || true
	@df -h . | tail -n 1
