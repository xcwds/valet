# Contributing

Valet is a proof of concept. Read the [design](docs/rfc/0001-design.md) first; its numbered
decisions are binding until a PR changes them.

## Setup

You need Go and golangci-lint at the versions in `mise.toml` (`mise install` sets both up; `go`
also fetches the `toolchain` from `go.mod` by itself), `git`, and Docker for the devcontainer and
end-to-end tests. Or open the repo in its devcontainer, which has all of it.

Build and run:

```sh
go build -o bin/valet ./cmd/valet
ln -sf valet bin/valetd
bin/valet version
bin/valetd
```

## Checks

Run before every push:

```sh
go mod tidy -diff && go build ./... && go vet ./... && golangci-lint run && go test -race ./...
```

CI also runs `govulncheck ./...` and checks that a `CGO_ENABLED=0` build is statically linked
(`modernc.org/sqlite` keeps Valet free of cgo). `golangci-lint fmt` fixes formatting.

## Pull requests

- One issue per PR, with `Closes #n` in the description.
- Security-relevant changes need negative tests (the denied case), not only happy paths.
- If a change alters a design decision, update `docs/rfc/0001-design.md` in the same PR.
- Never commit secrets, keys or tokens, including test fixtures that look real.

## License

Valet is licensed under [Apache-2.0](LICENSE). By contributing, you agree that your contributions
are licensed under it too (section 5 of the license). Files don't need per-file license headers;
the root `LICENSE` covers the repo.
