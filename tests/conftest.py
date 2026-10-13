import os

# Keep tests independent of any local .env (real Wazuh/ELK credentials, etc.).
os.environ.setdefault("CYBERUNIFY_DEMO", "1")
os.environ.setdefault("INGEST_INTERVAL_SECONDS", "0")
