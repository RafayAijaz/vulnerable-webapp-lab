FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x entrypoint.sh
RUN useradd -m -u 1000 webuser && chown -R webuser:webuser /app

USER webuser

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
