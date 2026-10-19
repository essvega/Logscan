FROM python:3.13-slim

LABEL org.opencontainers.image.title="logscan" \
      org.opencontainers.image.description="Find, classify and enrich the IP addresses hidden in log files." \
      org.opencontainers.image.source="https://github.com/essvega/Logscan"

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home logscan

USER logscan
WORKDIR /logs
ENTRYPOINT ["logscan"]
CMD ["."]
