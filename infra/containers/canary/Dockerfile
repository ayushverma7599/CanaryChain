# Canary sidecar. Build from the repository root:
#   docker build -f infra/containers/canary/Dockerfile -t canarychain-canary .
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Docker CLI only (no daemon): used by host mode for the process canary's `docker exec`.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY infra/containers/canary/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --default-timeout=120 --retries 10 -r /app/requirements.txt
COPY app/security/ /app/app/security/
ENTRYPOINT ["python", "-m", "app.security.canary_service"]
CMD ["network"]
