# Multi-architecture Dockerfile for Chrontainer
# Optimized for ARM64 (Raspberry Pi 5) and AMD64

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
COPY app/ /app/
COPY templates/ /app/templates/

# Create data directory
RUN mkdir -p /data

# Expose port
EXPOSE 5000

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

# Run the application
CMD ["python", "main.py"]
