# LongClaw backend -- production image
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Non-root user
RUN useradd -m sentinel
USER sentinel

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# Single worker by default -- the APScheduler sweep lives inside the API
# process, so >1 worker means >1 sweep firing on the same schedule. If you
# scale up, set ENABLE_SCHEDULER=false on all but one process instead.
CMD ["gunicorn", "app.main:app", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "--workers", "1", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "60"]
