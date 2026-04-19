# --- Stage 1: Build ---
# Use the latest rust:alpine to support Rust Edition 2024
FROM rust:alpine AS builder

# Install build dependencies for C-based crates (sqlite, etc.)
RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /usr/src/app
COPY . .

# Build release binary
RUN cargo build --release

# --- Stage 2: Runtime ---
FROM alpine:latest

# Install runtime dependencies
# - ca-certificates: Required for HTTPS requests (DoH/RDAP)
# - tzdata: Required for correct log timestamps
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/domain-scanner /app/
# Copy static web assets
COPY --from=builder /usr/src/app/web /app/web

# Create empty directories for persistence
RUN mkdir -p /app/data /app/logs

# Expose the default web port
EXPOSE 3000

# Set the environment to run in non-interactive mode
ENV RUST_LOG=info

# Start the application
ENTRYPOINT ["/app/domain-scanner"]
CMD ["--port", "3000"]
