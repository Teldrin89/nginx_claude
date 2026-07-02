"""Gunicorn configuration for the dummy Flask app."""

import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('GUNICORN_PORT', '8080')}"
workers = int(os.environ.get("GUNICORN_WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"
timeout = 30
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# Forwarded headers from nginx
forwarded_allow_ips = "*"
proxy_allow_ips = "*"
