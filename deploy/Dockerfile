# syntax=docker/dockerfile:1
# Valet: one static binary (valetd when run as valetd, the CLI as valet) on
# distroless, non-root. Build from the repository root:
#   docker build -f deploy/Dockerfile -t ghcr.io/xcwds/valet:dev .

FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
# Modules come from the network, or from vendor/ when the context has one.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/xcwds/valet/internal/version.Version=${VERSION}" \
      -o /out/usr/local/bin/valet ./cmd/valet \
 && ln -s valet /out/usr/local/bin/valetd \
 && mkdir -m 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
# Links the package on ghcr.io to this repository (and its Actions access).
LABEL org.opencontainers.image.source="https://github.com/xcwds/valet" \
      org.opencontainers.image.description="Valet: a credential broker for AI coding agents" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build --chown=65532:65532 /out/ /
ENV VALET_DATA_DIR=/data
VOLUME /data
USER 65532:65532
# admin, agent (MCP, git), egress
EXPOSE 14400 14401 14402
ENTRYPOINT ["/usr/local/bin/valetd"]
