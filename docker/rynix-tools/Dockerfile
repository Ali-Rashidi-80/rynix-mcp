# Rynix tools sidecar — generic CLI names only (no upstream brand labels).
FROM alpine:3.20

RUN apk add --no-cache bash curl jq python3 py3-pip ca-certificates

# Generic Rynix-named probes (wrappers or lightweight scripts)
RUN mkdir -p /opt/rynix/bin
COPY bin/ /opt/rynix/bin/
ENV PATH="/opt/rynix/bin:${PATH}"

WORKDIR /workspace
CMD ["sh", "-c", "echo rynix-tools ready; exec sleep infinity"]
