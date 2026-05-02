FROM python:3.11-slim

WORKDIR /app

COPY collector.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "collector.py"]