FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/sifen-minisender

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    libffi-dev \
    libjpeg62-turbo-dev \
    libssl-dev \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    xmlsec1 \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/sifen-minisender/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /opt/sifen-minisender/requirements.txt

COPY . /opt/sifen-minisender
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    mkdir -p /opt/sifen-minisender/artifacts \
             /opt/sifen-minisender/backups \
             /opt/sifen-minisender/secrets \
             /opt/sifen-minisender/assets

EXPOSE 5055

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
