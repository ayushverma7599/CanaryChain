FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd -u 10001 -M -s /usr/sbin/nologin tenant \
 && mkdir /data && chown 10001:10001 /data
COPY tenant.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["/app/entrypoint.sh"]
