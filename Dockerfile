# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy project
COPY . .

# Install system deps (for faiss, spacy)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Install Python deps with progress
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy model
RUN python -m spacy download en_core_web_trf

# Download knowledge data
RUN python setup.py --download-only

# Expose port (if you add API later)
# EXPOSE 8000

# Run the app
CMD ["python", "setup.py"]
