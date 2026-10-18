FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssl tzdata && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 10001 status && useradd -r -u 10001 -g status status && mkdir /data && chown status:status /data
COPY --chown=status:status app.py /app/app.py
COPY --chown=status:status static /app/static
USER 10001:10001
EXPOSE 8080
CMD ["python", "/app/app.py"]
