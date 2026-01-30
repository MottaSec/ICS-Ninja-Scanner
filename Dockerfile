FROM python:3.12-slim

# Install system dependencies for snap7 and nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libsnmp-dev \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY ics_scanner.py ./
COPY scanners/ ./scanners/
COPY utils/ ./utils/

# Install with all optional dependencies
RUN pip install --no-cache-dir -e ".[all]"

ENTRYPOINT ["ics-ninja"]
CMD ["--help"]
