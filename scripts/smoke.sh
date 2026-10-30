#!/usr/bin/env bash
# Builds the SDK the way a dependent project would and exercises it end to end
# against a loopback httptest server: no testnet, no external network.
#
#   scripts/smoke.sh
#
# A temporary module outside the repository requires the SDK through a
# replace directive, so the module path, exported API and go.sum are all what
# a consumer would see.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cp "$repo/scripts/smoke_consumer.go.txt" "$work/main.go"
cp "$repo/go.sum" "$work/go.sum"
cat > "$work/go.mod" <<MOD
module smoke.example/consumer

go $(go list -m -f '{{.GoVersion}}' -modfile="$repo/go.mod")

require github.com/activeledger/SDK-Golang/v2 v2.0.0

replace github.com/activeledger/SDK-Golang/v2 => $repo
MOD

cd "$work"
# GOPROXY=off: resolves from the module cache only, so a missing dependency
# fails loudly instead of reaching for the network.
GOFLAGS=-mod=mod GOPROXY=off go mod tidy
GOFLAGS=-mod=mod GOPROXY=off go run .
