FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential libpcap-dev && rm -rf /var/lib/apt/lists/*

# Copy requirements FIRST for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directory structure BEFORE copying
RUN mkdir -p /opt/ids-detector/scripts /opt/ids-detector/models

# Copy scripts
COPY scripts/*.py /opt/ids-detector/scripts/

# ✅ Copy models (this is already in your file!)
COPY models/ /opt/ids-detector/models/

# Copy the rest of the application code LAST
COPY api_server_with_results.py .
COPY api_server.py .
COPY credentials.csv .
COPY manage_ids.sh .
# Add other files you need

EXPOSE 8080
CMD ["python", "api_server_with_results.py"]