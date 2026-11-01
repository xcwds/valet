# An agent container with no GitHub credentials: git, MCP and package
# registries all go through Valet. The valet CLI comes from Valet's image.
ARG VALET_IMAGE=ghcr.io/xcwds/valet:dev
FROM ${VALET_IMAGE} AS valet

FROM mcr.microsoft.com/devcontainers/base:bookworm
COPY --from=valet /usr/local/bin/valet /usr/local/bin/valet
COPY valet-setup.sh /usr/local/bin/valet-setup
