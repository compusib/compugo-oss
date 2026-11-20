#!/usr/bin/env bash
# The module's tests under Yaegi, as Traefik interprets a plugin: every package by its import path, in a GOPATH
# layout (Yaegi reads no go.mod). Run it from anywhere: `libs/traefik/yaegi-test.sh`.
set -euo pipefail

cd "$(dirname "$0")"
module=$(go list -m)
gopath=$(mktemp -d)
trap 'rm -rf "$gopath"' EXIT
mkdir -p "$gopath/src/$(dirname "$module")"
ln -s "$PWD" "$gopath/src/$module"

for package in $(go list ./...); do
  echo "yaegi test $package"
  (cd "$gopath/src/$package" && GOPATH="$gopath" yaegi test -v .)
done
