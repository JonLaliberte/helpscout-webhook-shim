FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask waitress

COPY relay.py .

# Bind to loopback only: cloudflared reaches us on 127.0.0.1:9100, nothing else can.
EXPOSE 9100
CMD ["waitress-serve", "--host=127.0.0.1", "--port=9100", "relay:app"]
