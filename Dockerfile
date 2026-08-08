FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PORT=8080 \
    POLICYFORGE_DATA=/var/lib/policyforge

RUN addgroup -S policyforge && adduser -S -G policyforge policyforge
WORKDIR /app
COPY --chown=policyforge:policyforge src ./src
RUN mkdir -p /var/lib/policyforge && chown policyforge:policyforge /var/lib/policyforge
USER policyforge
EXPOSE 8080
VOLUME ["/var/lib/policyforge"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2)"
CMD ["python", "-m", "policyforge.server"]
