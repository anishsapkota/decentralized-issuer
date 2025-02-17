# Build stage
FROM rust:latest as builder 

WORKDIR /app

# Copy source files
# Copy only Cargo files first to cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY certs/ ./certs/
COPY metadata/ ./metadata/
COPY src/ ./src/

# Build the actual application
RUN cargo build --release

# Runtime stage
FROM debian:latest


WORKDIR /app

# Copy built binary from builder stage
COPY --from=builder /app/target/release/issuer-frontend /app/issuer-frontend
COPY --from=builder /app/certs /app/certs 
COPY --from=builder /app/metadata /app/metadata

RUN apt-get update && apt-get install -y \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Expose HTTP server port
EXPOSE 3000

# Environment variables
ENV RUST_LOG=info
ENV HOST=0.0.0.0:3000
# Entrypoint
ENTRYPOINT ["/app/issuer-frontend"]
