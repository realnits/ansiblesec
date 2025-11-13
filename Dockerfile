FROM rust:1.75 as builder

WORKDIR /usr/src/ansiblesec

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/ansiblesec/target/release/ansiblesec /usr/local/bin/ansiblesec

# Create non-root user
RUN useradd -m -u 1000 ansiblesec

USER ansiblesec
WORKDIR /workspace

ENTRYPOINT ["ansiblesec"]
CMD ["--help"]
