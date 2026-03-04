FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable stdout/stderr unbuffered
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       gcc \
       libssl-dev \
       libffi-dev \
       curl \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency manifests
COPY requirements.txt backend/requirements.txt /app/

RUN pip install --upgrade pip setuptools wheel
RUN pip install -r requirements.txt -r backend/requirements.txt

# Copy application code
COPY . /app

ENV FLASK_ENV=production
ENV MODEL_PATH=/app/models/phishing_model.pkl

EXPOSE 8000

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "backend.app:app", "--workers", "4", "--threads", "2", "--timeout", "120"]
