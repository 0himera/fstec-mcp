# Dockerfile для FSTEC Excel Search MCP Server
FROM python:3.11-slim

# Метаданные
LABEL maintainer="FSTEC MCP Server"
LABEL description="MCP сервер для поиска уязвимостей в базе ФСТЭК"

# Установка рабочей директории
WORKDIR /app

# Копируем requirements первым для кеширования слоёв
COPY requirements.txt .

# Установка зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY mcp_instance.py .
COPY server.py .
COPY tools/ ./tools/

# Копируем файл базы данных (должен быть в директории сборки)
COPY vullist.xlsx .

# Порт по умолчанию
ENV PORT=8000
ENV VULLIST_PATH=/app/vullist.xlsx

# Открываем порт
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/mcp')" || exit 1

# Запуск сервера
CMD ["python", "server.py"]
