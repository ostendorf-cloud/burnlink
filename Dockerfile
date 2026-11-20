# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

# Frontend stage: builds the Vue SPA bundle straight into cmd/burnlink/dist, the
# same path "task web:build" writes to locally. The Go build stage below only
# ever copies that directory out, never runs Node itself.
#
# Digest for node:26.13.1-bookworm-slim (linux/amd64); re-resolve with
# "docker buildx imagetools inspect node:26.13.1-bookworm-slim" if this patch
# version ever moves. Not re-verified against the live registry from this
# sandbox; carried over from the scaffold spec as-is.
FROM node:26.13.1-bookworm-slim@sha256:18a166e2d50578afe933434857ed2d9059bd1aa398a223e9c89eb4302354f079 AS frontend

WORKDIR /src/web

# corepack no longer ships with Node: the Node.js TSC voted to stop bundling it
# by default starting with Node.js 25 (nodejs/corepack#722). npm still ships,
# so npm installs corepack first, then corepack installs the pinned pnpm
# version below, the exact one mise.toml's "pnpm" tool resolves to, so the
# lockfile this stage reads was written by the same pnpm a local "task setup"
# installs.
RUN npm install -g corepack@0.36.0 && corepack enable && corepack prepare pnpm@12.19.0 --activate

COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY web/ ./

RUN pnpm run build

# Digest for golang:1.27.4-bookworm (linux/amd64), matching mise.toml's pinned
# Go patch exactly. Not re-verified against the live registry from this
# sandbox; carried over from the scaffold spec as-is.
FROM golang:1.27.4-bookworm@sha256:fb7cceb528b47141eccd9b60bf3cbd27d5ef5f8cf5b7d338bec866da495b50dc AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=frontend /src/cmd/burnlink/dist cmd/burnlink/dist

# VERSION and COMMIT feed the build endpoint. Without them it reports "unknown",
# because the build context has no .git directory for the toolchain to read.
ARG VERSION=""
ARG COMMIT=""
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/ostendorf-cloud/burnlink/internal/buildinfo.Version=${VERSION} -X github.com/ostendorf-cloud/burnlink/internal/buildinfo.Commit=${COMMIT}" \
    -o /out/burnlink ./cmd/burnlink

# distroless/static-debian12 carries only a minimal root filesystem,
# ca-certificates and tzdata, no shell, no package manager. The ":nonroot" tag
# runs as uid/gid 65532, not root.
#
# Digest for gcr.io/distroless/static-debian12:nonroot (linux/amd64). Not
# re-verified against the live registry from this sandbox; carried over from
# the scaffold spec as-is. Re-resolve with "docker buildx imagetools inspect
# gcr.io/distroless/static-debian12:nonroot" if this needs refreshing.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d

COPY --from=build /out/burnlink /usr/local/bin/burnlink

# Matches the public listener and govue's own admin listener (health,
# readiness, metrics); see cmd/burnlink/main.go.
EXPOSE 8080
EXPOSE 8081

# Numeric, not "nonroot:nonroot": the same uid/gid the base image's own
# nonroot user already resolves to, redundant but kept explicit.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/burnlink"]
