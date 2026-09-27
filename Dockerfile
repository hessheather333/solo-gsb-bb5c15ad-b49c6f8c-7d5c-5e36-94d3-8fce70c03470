FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    QUOTA_DB_PATH=/data/quota.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# SQLite 数据目录，由 compose 挂载命名卷持久化
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# 单 worker + uvicorn 事件循环；所有写操作由 SQLite BEGIN IMMEDIATE
# 事务串行化，单进程即可安全承载高并发裁决，且无多进程协调开销。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
