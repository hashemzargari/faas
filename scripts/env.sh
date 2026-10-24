#!/usr/bin/env bash
# Source this before running go commands in this repo:
#   source scripts/env.sh
#
# The file sandbox only guarantees writes inside the workspace, so the Go build
# and module caches live here instead of in $HOME.
set -a
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || return 1
export GOPATH="$PWD/.gopath"
export GOMODCACHE="$PWD/.gopath/pkg/mod"
export GOCACHE="$PWD/.gocache"
export GOFLAGS="${GOFLAGS:--mod=vendor}"
set +a
