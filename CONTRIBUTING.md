# Contributing

Valet is a proof of concept. Read the [design](docs/rfc/0001-design.md) first; its numbered
decisions are binding until a PR changes them.

## Setup

You need Go (the version is pinned by the repo setup issue in `go.mod` and `mise.toml`),
`golangci-lint`, `git` and Docker (for the devcontainer and end-to-end tests).

## Checks

Run before every push:

```sh
go build ./... && go vet ./... && golangci-lint run && go test -race ./...
```

## Pull requests

- One issue per PR, with `Closes #n` in the description.
- Security-relevant changes need negative tests (the denied case), not only happy paths.
- If a change alters a design decision, update `docs/rfc/0001-design.md` in the same PR.
- Never commit secrets, keys or tokens, including test fixtures that look real.

## License

Valet is licensed under [Apache-2.0](LICENSE). By contributing, you agree that your contributions
are licensed under it too (section 5 of the license). Files don't need per-file license headers;
the root `LICENSE` covers the repo.
