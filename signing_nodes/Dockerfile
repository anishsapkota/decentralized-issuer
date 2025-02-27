# Build stage
FROM rust:latest as builder 

WORKDIR /app

# Copy source files
# Copy only Cargo files first to cache dependencies
COPY Cargo.toml Cargo.lock ./

COPY src/ ./src/

# Build the actual application
RUN cargo build --release

# Runtime stage
FROM debian:latest


WORKDIR /app

# Copy built binary from builder stage
COPY --from=builder /app/target/release/nodes /app/nodes

# Create and configure keys directory
RUN mkdir -p /app/keys
VOLUME /app/keys

RUN apt-get update && apt-get install -y \
    iputils-ping \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Expose HTTP server port
EXPOSE 3030

# Environment variables
ENV RUST_LOG=info
ENV KAFKA_BROKER=kafka:9092
# Entrypoint
ENTRYPOINT ["/app/nodes"]
