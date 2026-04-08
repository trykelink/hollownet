FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/

RUN adduser --disabled-password --gecos "" appuser \
    && mkdir -p /app/models \
    && chown -R appuser:appuser /app

USER appuser

CMD ["python", "train.py"]
