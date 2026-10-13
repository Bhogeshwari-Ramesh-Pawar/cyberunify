FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    CYBERUNIFY_DB=/data/cyberunify.db CYBERUNIFY_KEY_FILE=/data/.cyberunify.key
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as an unprivileged user; the database and the credential key live in a volume.
RUN useradd --create-home --uid 10001 cyberunify && mkdir /data && chown cyberunify /data
USER cyberunify
VOLUME /data

EXPOSE 8000 5514/udp 5514/tcp
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/catalog')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
