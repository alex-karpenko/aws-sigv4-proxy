ARG RUST_VERSION=1.88-bookworm
FROM rust:${RUST_VERSION} AS builder

WORKDIR /src
COPY . .

RUN cargo build --release
RUN strip target/release/aws-sigv4-proxy

# Runtime stage
FROM gcr.io/distroless/cc-debian12

USER nobody
WORKDIR /app
COPY --from=builder /src/target/release/aws-sigv4-proxy /app/

ENTRYPOINT ["/app/aws-sigv4-proxy"]
CMD ["--help"]
