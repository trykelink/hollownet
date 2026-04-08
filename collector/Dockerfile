FROM python:3.12-slim

WORKDIR /opt/hollownet

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Place source under collector/app/ so that `collector.app.*` is importable
# from the WORKDIR, matching the same package layout used in development.
COPY app/ ./collector/app/

RUN adduser --disabled-password --gecos "" appuser
USER appuser

CMD ["uvicorn", "collector.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
