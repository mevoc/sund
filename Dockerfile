# syntax=docker/dockerfile:1

# --- build: fully static, pure-Go SQLite means no cgo and no C toolchain ---
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads separately from the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=0.0.0-docker
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/sund .

# A data directory for the database, owned by the distroless nonroot uid (65532).
RUN mkdir -p /data

# --- runtime: distroless static gives a tiny, non-root image with CA certs
#     (the server makes outbound HTTPS calls to push distributors) ---
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source="https://github.com/mevoc/sund" \
      org.opencontainers.image.description="Sund — blind store-and-forward relay for E2E-encrypted messages between a user's devices"

COPY --from=build /out/sund /sund
COPY --from=build --chown=65532:65532 /data /data

# Defaults suit a container: listen on all interfaces, keep the database and the
# pinned CA on the /data volume so both survive a container replacement. Pinned
# TLS is the default; set SUND_HTTP=1 to serve plain HTTP behind a
# TLS-terminating proxy (WebPKI mode). Override with flags or these vars.
ENV SUND_ADDR=:5870 \
    SUND_DB=/data/sund.db \
    SUND_TLS_DIR=/data/tls

EXPOSE 5870
VOLUME ["/data"]
USER nonroot:nonroot
ENTRYPOINT ["/sund"]
CMD ["serve"]
