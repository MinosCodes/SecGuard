FROM python:3.12-slim

WORKDIR /app

RUN useradd --system --create-home --shell /usr/sbin/nologin secguard

COPY pyproject.toml README.md config.yaml ./
COPY src ./src
COPY samples ./samples

RUN pip install --no-cache-dir . && \
    mkdir -p /app/reports /app/.cache && \
    chown -R secguard:secguard /app

USER secguard

ENTRYPOINT ["secguard"]
CMD ["models"]
