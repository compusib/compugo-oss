# compugo-oss

Open-source Go by Compusib. One module per library under `libs/<name>` and per program under `apps/<name>`; each has
its own license in its directory and is released by the tag `<libs|apps>/<name>/v<version>`.

| Module | What it is | License |
|---|---|---|
| [`libs/traefik`](libs/traefik) | The settings of a Traefik plugin, normalized: the short forms a label or a `Middleware` object is written in go in, one form comes out, and what cannot be read is refused with an error that names the key. `settings` is the engine, `policy` the settings of the plugin `policy`. | MIT |

## libs/traefik

```go
import "github.com/compusib/compugo-oss/libs/traefik/policy"

normalized, err := policy.Normalize(map[string]any{"Scopes": "admin.cluster", "Missing": "login"})
```

It is plain Go on the standard library, because a Traefik plugin runs interpreted, under Yaegi, and vendors what it
uses. Its tests run under Go and under Yaegi:

```sh
cd libs/traefik
go vet ./... && go test ./...
./yaegi-test.sh
```

Go and Yaegi are pinned in `mise.toml` (`mise install`).
