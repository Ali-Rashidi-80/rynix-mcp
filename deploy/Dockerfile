FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY rynix-core /app/rynix-core
RUN cargo build --release --manifest-path /app/rynix-core/Cargo.toml

FROM python:3.12-slim

RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY mcp-server /app/mcp-server
COPY profiles /app/profiles
COPY plugins /app/plugins
COPY schemas /app/schemas
COPY templates /app/templates
COPY --from=builder /app/rynix-core/target/release/rynix-scan /usr/local/bin/rynix-scan

RUN pip install --no-cache-dir uv \
    && cd mcp-server && uv sync

ENV RYNIX_PROFILES_DIR=/app/profiles
ENV RYNIX_PLUGINS_DIR=/app/plugins
ENV RYNIX_SCHEMAS_DIR=/app/schemas
ENV RYNIX_TEMPLATES_DIR=/app/templates
ENV RYNIX_SCANNER_BIN=/usr/local/bin/rynix-scan

USER app
ENV UV_NO_SYNC=1
EXPOSE 8090
CMD ["uv", "run", "--no-sync", "--directory", "mcp-server", "python", "-m", "rynix_mcp.serve", "--serve", "--host", "0.0.0.0", "--port", "8090"]
