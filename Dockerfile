# Build Stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install dependencies required for building wheels (e.g., cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Patch build tools to prevent compiling vulnerable wheels
RUN pip install --no-cache-dir --upgrade pip "setuptools>=78.1.1" "wheel>=0.46.2" "jaraco.context>=6.1.0" "msgpack>=1.2.1"

COPY pyproject.toml ./
COPY lobster/ ./lobster/

# Build wheel and explicitly constrain vulnerable transitive dependencies
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels . "wheel>=0.46.2" "jaraco.context>=6.1.0" "setuptools>=78.1.1" "msgpack>=1.2.1"

# Production Stage
FROM python:3.11-slim

WORKDIR /app

# Patch base python packages for Trivy CVEs
RUN pip install --no-cache-dir --upgrade pip "setuptools>=78.1.1" "wheel>=0.46.2" "jaraco.context>=6.1.0" "msgpack>=1.2.1"

# Create a non-root user for security
RUN groupadd -r lobster && useradd -r -g lobster lobster

# Copy built wheels from builder
COPY --from=builder /build/wheels /wheels
COPY --from=builder /build/pyproject.toml /app/
COPY --from=builder /build/lobster /app/lobster/

# Install from wheels and clean up
RUN pip install --no-cache /wheels/* && rm -rf /wheels

# Set ownership
RUN chown -R lobster:lobster /app

# Switch to non-root user
USER lobster

# Set environment defaults
ENV LOBSTER_LOG_PAYLOADS=false
ENV PYTHONUNBUFFERED=1

# Healthcheck to verify the Python module can load successfully
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["lobster-proxy", "--health"]

# Default entrypoint
ENTRYPOINT ["lobster-proxy"]
