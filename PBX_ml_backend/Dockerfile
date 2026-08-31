FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for LightGBM & SQLite
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn gevent gevent-websocket

COPY . .

EXPOSE 5000

CMD ["python", "src/monitor.py"]
