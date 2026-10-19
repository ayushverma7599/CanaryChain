FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY gateway.py /app/gateway.py
WORKDIR /app
USER 10001:10001
CMD ["python", "/app/gateway.py"]
