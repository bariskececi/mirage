FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Decoy ports + dashboard. Map these when you run the container.
EXPOSE 502 102 3000

# Drop privileges; bind to high ports inside, remap on the host if you want 502/102.
ENV MIRAGE_MODBUS_PORT=502 \
    MIRAGE_S7_PORT=102 \
    MIRAGE_DASH_PORT=3000

CMD ["python", "run.py"]
