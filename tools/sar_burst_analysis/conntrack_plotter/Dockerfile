FROM python:3.11-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY plot_server.py .

ENV DATA_DIR=/data \
    OUT_DIR=/out \
    MAPPING_PATH=/data/mapping.json \
    PORT=8080 \
    MAX_POINTS=4000 \
    PYTHONUNBUFFERED=1

EXPOSE 8080
VOLUME ["/data", "/out"]

# Pre-generate static HTML, then serve API + dashboard via gunicorn
CMD ["bash", "-c", "python3 plot_server.py --data-dir /data --out-dir /out --generate-only && exec gunicorn -b 0.0.0.0:${PORT:-8080} -w 1 --timeout 120 'plot_server:app'"]