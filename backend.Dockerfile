# Use a lightweight Debian-based Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies (YARA needs a C-compiler to build from source occasionally)
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

# Copy the requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only the files the API needs (We exclude Binary Ninja specific files)
COPY api.py .
COPY database.py .
COPY models.py .
COPY config.py .
COPY errors.py .

# Expose the API port
EXPOSE 8000

# Start the API server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]