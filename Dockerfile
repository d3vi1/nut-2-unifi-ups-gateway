# syntax=docker/dockerfile:1.12.1@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25

FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOARM="${TARGETVARIANT#v}" \
    go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=$VERSION -X main.revision=$REVISION -X main.buildDate=$BUILD_DATE" \
      -o /out/nut-2-unifi-ups-gateway ./cmd/nut-2-unifi-ups-gateway && \
    mkdir -p /out/state

FROM scratch

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="NUT 2 UniFi UPS Gateway" \
      org.opencontainers.image.description="Read-only Network UPS Tools to UniFi Network UPS gateway" \
      org.opencontainers.image.source="https://github.com/d3vi1/nut-2-unifi-ups-gateway" \
      org.opencontainers.image.licenses="GPL-2.0-only" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$BUILD_DATE"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/state /var/lib/n2u
COPY --from=build --chown=65532:65532 /out/nut-2-unifi-ups-gateway /nut-2-unifi-ups-gateway
COPY LICENSE /licenses/GPL-2.0-only.txt

USER 65532:65532
EXPOSE 9199/tcp
VOLUME ["/var/lib/n2u"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/nut-2-unifi-ups-gateway", "healthcheck"]

ENTRYPOINT ["/nut-2-unifi-ups-gateway"]
