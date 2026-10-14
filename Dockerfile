# TxWarden in a container. Build:   docker build -t txwarden .
# Review a file:                    docker run --rm -v "$PWD:/work" txwarden review examples/approve_unlimited.json --no-llm
# MCP server on stdio:              docker run --rm -i txwarden mcp --rpc http://host.docker.internal:8545
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
 && useradd --create-home --uid 10001 txwarden

COPY examples /app/examples
USER txwarden
WORKDIR /work
ENTRYPOINT ["txwarden"]
CMD ["--help"]
