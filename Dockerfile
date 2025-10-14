FROM debian:bookworm-slim AS builder

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    gcc \
    pkg-config \
    libjansson-dev \
    libmicrohttpd-dev \
    libsodium-dev \
    libcurl4-openssl-dev \
    git \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy entire repository for git information
COPY . .

# Build the application with optimization flags
RUN cmake -DCMAKE_BUILD_TYPE=Release . && make -j$(nproc)

# Use the same Debian version for runtime to ensure library compatibility
FROM debian:bookworm-slim AS runtime

# Install only runtime dependencies
RUN apt-get update && apt-get install -y \
    libjansson4 \
    libmicrohttpd12 \
    libsodium23 \
    libcurl4 \
    netcat-traditional \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/share/doc /usr/share/man \
    && find /var/cache -type f -delete

WORKDIR /app

# Copy only the built binary and necessary files from builder
COPY --from=builder /build/datum_gateway /app/
COPY --from=builder /build/www/ /app/www/
COPY --from=builder /build/doc/example_datum_gateway_config.json /app/config/config.json

# Create a configuration directory if it doesn't exist
RUN mkdir -p /app/config

# Verify shared library dependencies
RUN ldd /app/datum_gateway

# Create a non-root user
RUN useradd -r -s /bin/false datumuser && \
    chown -R datumuser:datumuser /app

# Change to non-root user
USER datumuser

# Set up healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD nc -zv localhost 23334 || exit 1

# Expose ports
EXPOSE 23334/tcp 7152/tcp

# Create a volume for configuration and data
VOLUME ["/app/config"]

# Set the entrypoint
ENTRYPOINT ["/app/datum_gateway", "--config", "/app/config/config.json"]
