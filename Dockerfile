FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies (利用 Docker 缓存层)
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy agent code
COPY agent.py .
COPY examples/ examples/

# Identity + memory persist via volume
VOLUME /app/data

# Default env (可被 --env-file 覆盖)
ENV CIVITASOS_URL=http://node1:8099 \
    AGENT_NAME=CivitasAgent \
    AGENT_LLM=ollama:qwen3:latest \
    LLM_BASE_URL=http://host.docker.internal:11434/v1 \
    AGENT_CAPABILITIES=general \
    GATEWAY_PORT=8300 \
    AGENT_IDENTITY=/app/data/identity.key \
    AGENT_DATA_DIR=/app/data \
    LOG_LEVEL=INFO

EXPOSE 8300

ENTRYPOINT ["python", "agent.py"]
