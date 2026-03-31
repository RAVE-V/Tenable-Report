# Use a pinned Python 3.11 slim image for reproducibility and security
FROM python:3.11.8-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Create a non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# Set work directory
WORKDIR /app

# Install system dependencies and clean up
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories and set ownership before copying project files
RUN mkdir -p reports .cache data && chown -R appuser:appgroup /app

# Copy project files
COPY . .
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Define the entrypoint to the CLI tool
ENTRYPOINT ["python", "-m", "src.cli"]

# Default command if no arguments are provided
CMD ["--help"]
