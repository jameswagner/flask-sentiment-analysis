FROM 094573088890.dkr.ecr.us-east-1.amazonaws.com/python-3.11-slim:latest

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]