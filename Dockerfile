FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download model + data
RUN python setup.py --download-only

CMD ["python", "-m", "src.main", "--model", "all-mpnet-base-v2"]
