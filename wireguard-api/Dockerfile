FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wireguard \
    wireguard-tools \
    iptables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create directory for WireGuard configs
RUN mkdir -p /etc/wireguard

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

