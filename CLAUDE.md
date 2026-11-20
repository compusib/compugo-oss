# CLAUDE.md — compugo-oss

Open-source Go: libraries, and programs, that others may use.

## Layout

- A `go.work` at the root; one module per library under `libs/<name>` and per program under `apps/<name>`.
- A module is `github.com/compusib/compugo-oss/<libs|apps>/<name>`, released by the git tag
  `<libs|apps>/<name>/v<version>`. The first version is `v0.1.0`. A major version is never crossed, `0.x` to
  `1.0.0` least of all, without the maintainer's explicit decision.
- Go and Yaegi are mise's, pinned in `mise.toml` to what Traefik is built with. Nothing else names a version of
  either; the workflows install from `mise.toml`.
- **The license is per library**, in the library's module (`libs/<name>/LICENSE`): the most liberal license that
  stays compatible with the upstream the library serves. `libs/traefik` is MIT.

## What holds for code that a Traefik plugin vendors (`libs/traefik`)

- **Standard library only, and plain Go.** A plugin runs interpreted, under Yaegi. No dependency, no cgo, no
  `unsafe`. Anything newer than plain Go is checked by running it under Yaegi.
- **The tests pass under Go and under Yaegi**, here and on GitHub: `go vet ./... && go test ./...`, then
  `./yaegi-test.sh` in the module (every package by its import path, in a `GOPATH` layout).
- **Yaegi is not Go.** What it got wrong is written where it was worked around (`settings.readField`: the error of
  a call whose results are returned converted to `any` is lost). A test that passes under Go alone proves nothing
  for a plugin.
- **Each default and each field name is written in one place.** In `libs/traefik/policy` that is the block of
  constants and the description under it (the settings' keys and defaults) and the JSON tags of the types (the
  names of the normalized form).
- **The grammar is the contract** (the package comment of `settings`). Every form a setting may be written in is
  a test, as labels and as a cluster's object, and every refusal with its exact message
  (`policy/policy_test.go`). A change to the grammar changes its test first.
- **`libs/traefik` normalizes and refuses.** Matching a request against rules and deciding are not this
  library's.

## Commits

- Conventional commits. **No `Co-Authored-By` and no other AI or tool attribution.**
- Ask the maintainer before tagging a release.
