FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libffi-dev \
    libjpeg62-turbo-dev \
    libssl-dev \
    libxml2-dev \
    libxmlsec1 \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    xmlsec1 \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt

RUN pip install --upgrade pip && \
    pip install -r /app/requirements.txt

COPY . /app

ARG UID=1000
ARG GID=1000
RUN groupadd --gid "${GID}" app && \
    useradd --uid "${UID}" --gid app --create-home --shell /bin/bash app && \
    mkdir -p /data /secrets /app/backups /app/assets && \
    chown -R app:app /app /data /secrets

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER app

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["webui"]
