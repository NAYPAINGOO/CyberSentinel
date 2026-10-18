FROM python:3.12-slim
WORKDIR /app
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt && useradd --create-home sentinel
COPY --chown=sentinel:sentinel . .
RUN mkdir -p /data && chown sentinel:sentinel /data
USER sentinel
ENV CYBER_DB=/data/sentinel.db
EXPOSE 8000
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8000", "--call", "sentinel:create_app"]
