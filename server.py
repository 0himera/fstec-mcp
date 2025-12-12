"""MCP сервер для поиска уязвимостей ФСТЭК в Excel базе данных."""
# Standard library
import os
from typing import Dict, Any

# Third-party
from dotenv import load_dotenv, find_dotenv

# Load environment variables
load_dotenv(find_dotenv())

from fastmcp import FastMCP, Context
from opentelemetry import trace

# Импортируем единый экземпляр FastMCP
from mcp_instance import mcp

# Константы
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")
VULLIST_PATH = os.getenv("VULLIST_PATH", "vullist.xlsx")

# OpenTelemetry tracer
tracer = trace.get_tracer(__name__)


def init_tracing():
    """Инициализация OpenTelemetry для трейсинга."""
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
    
    provider = TracerProvider()
    processor = SimpleSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)


def init_data():
    """Предзагрузка данных ФСТЭК в память при старте сервера."""
    from tools.utils import FSTECDataLoader
    
    try:
        loader = FSTECDataLoader.get_instance(VULLIST_PATH)
        print(f"📊 База данных успешно загружена в память")
        return True
    except FileNotFoundError as e:
        print(f"❌ ОШИБКА: {e}")
        print("Сервер не может быть запущен без файла базы данных.")
        return False
    except Exception as e:
        print(f"❌ Неожиданная ошибка при загрузке данных: {e}")
        return False


# Инициализация трейсинга
init_tracing()

# Импортируем инструменты (регистрация через декоратор @mcp.tool())
from tools.search_vulnerabilities import search_vulnerabilities
from tools.get_vulnerability_details import get_vulnerability_details


# Добавляем промпты
@mcp.prompt()
def search_prompt(software: str = "") -> str:
    """Промпт для поиска уязвимостей конкретного ПО."""
    return f"""Найди уязвимости для программного обеспечения: {software}

Используй инструмент search_vulnerabilities с запросом "{software}".
После получения списка, если нужна детальная информация, 
используй get_vulnerability_details с конкретным BDU ID."""


@mcp.prompt()
def analyze_prompt(bdu_id: str = "") -> str:
    """Промпт для анализа конкретной уязвимости."""
    return f"""Проанализируй уязвимость {bdu_id}.

Используй инструмент get_vulnerability_details с идентификатором "{bdu_id}".
Предоставь краткую сводку:
1. Что за уязвимость
2. Какое ПО затронуто
3. Уровень опасности
4. Рекомендации по устранению"""


def main():
    """Запуск MCP сервера с HTTP транспортом."""
    print("=" * 60)
    print("🔒 FSTEC EXCEL SEARCH MCP SERVER")
    print("=" * 60)
    
    # Предзагружаем данные
    if not init_data():
        print("=" * 60)
        print("❌ Сервер остановлен из-за ошибки загрузки данных")
        print("=" * 60)
        return
    
    print("=" * 60)
    print(f"🚀 MCP Server: http://{HOST}:{PORT}/mcp")
    print("=" * 60)
    print("📌 Доступные инструменты:")
    print("   - search_vulnerabilities: Поиск уязвимостей по ключевым словам")
    print("   - get_vulnerability_details: Получение детальной информации по BDU ID")
    print("=" * 60)
    
    # Запускаем MCP сервер с streamable-http транспортом
    mcp.run(transport="streamable-http", host=HOST, port=PORT, stateless_http=True)


if __name__ == "__main__":
    main()
