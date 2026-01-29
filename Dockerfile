# Multi-architecture Dockerfile for Chrontainer
# Optimized for ARM64 (Raspberry Pi 5) and AMD64

FROM node:20-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app/ /app/app/
COPY templates/ /app/templates/
COPY wsgi.py /app/
COPY gunicorn.conf.py /app/

# Copy built frontend assets
COPY --from=frontend-build /frontend/dist /app/frontend/dist

# Create data directory
RUN mkdir -p /data

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=5000
ENV LOG_LEVEL=INFO

# Run the application with Gunicorn
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:application"]
