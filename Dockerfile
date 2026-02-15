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

COPY . /app

RUN pip install --upgrade pip && \
    if [ -f /app/requirements.txt ]; then \
      pip install -r /app/requirements.txt; \
    elif [ -f /app/pyproject.toml ]; then \
      pip install /app; \
    else \
      echo "No dependency file found (requirements.txt or pyproject.toml)." && exit 1; \
    fi

RUN addgroup --system app && adduser --system --ingroup app app && \
    mkdir -p /app/artifacts /app/backups /app/secrets /app/data /app/assets && \
    chown -R app:app /app

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER app

EXPOSE 5055

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["help"]
