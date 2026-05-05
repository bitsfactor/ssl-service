FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --break-system-packages -r requirements.txt

COPY app ./app

# PORT is supplied by the platform via .env; expose it for clarity.
ENV PORT=8080
EXPOSE 8080

CMD ["python", "-m", "app"]
