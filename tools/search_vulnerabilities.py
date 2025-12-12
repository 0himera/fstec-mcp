"""Инструмент поиска уязвимостей ФСТЭК по ключевым словам."""
from fastmcp import Context
from mcp.types import TextContent
from opentelemetry import trace
from pydantic import Field

from mcp_instance import mcp
from .utils import ToolResult, FSTECDataLoader

# OpenTelemetry tracer
tracer = trace.get_tracer(__name__)


@mcp.tool(
    name="search_vulnerabilities",
    description="""🔍 Поиск уязвимостей в базе ФСТЭК по ключевым словам.

Ищет совпадения в полях: Название ПО, Версия ПО, Описание, Наименование, Вендор.
Поддерживает составные запросы через пробел (работает как логическое И).

Примеры запросов:
- "nginx" - найдёт всё про nginx
- "nginx 1.5.6" - найдёт уязвимости nginx именно для версии 1.5.6
- "1C Предприятие" - уязвимости в 1C
- "buffer overflow" - уязвимости переполнения буфера
"""
)
async def search_vulnerabilities(
    query: str = Field(
        ...,
        description="Поисковая фраза (например: 'nginx', '1C Предприятие', 'buffer overflow')"
    ),
    limit: int = Field(
        default=5,
        description="Максимальное количество результатов (по умолчанию: 5)"
    ),
    ctx: Context = None
) -> ToolResult:
    """
    🔍 Поиск списка уязвимостей по ключевым словам.
    
    Фильтрует записи базы данных ФСТЭК, где поисковая фраза содержится
    (case-insensitive) в колонках "Название ПО", "Описание" или "Наименование уязвимости".
    
    Args:
        query: Поисковая фраза для поиска
        limit: Ограничение количества возвращаемых результатов
        ctx: Контекст для логирования и отслеживания прогресса
        
    Returns:
        ToolResult: Список найденных уязвимостей (ID, Краткое название, Уровень опасности)
        
    Examples:
        >>> result = await search_vulnerabilities("Apache", 10, ctx)
        >>> print(result.content)
    """
    with tracer.start_as_current_span("search_vulnerabilities") as span:
        span.set_attribute("query", query)
        span.set_attribute("limit", limit)
        
        await ctx.info(f"🔍 Поиск уязвимостей по запросу: '{query}'")
        await ctx.report_progress(progress=0, total=100)
        
        try:
            # Получаем данные из кеша
            loader = FSTECDataLoader.get_instance()
            await ctx.report_progress(progress=25, total=100)
            
            # Выполняем поиск
            await ctx.info("📊 Выполняем поиск в базе данных...")
            results = loader.search(query, limit)
            await ctx.report_progress(progress=75, total=100)
            
            if results.empty:
                await ctx.info(f"⚠️ По запросу '{query}' ничего не найдено")
                span.set_attribute("results_count", 0)
                
                return ToolResult(
                    content=[TextContent(
                        type="text",
                        text=f"По запросу '{query}' ничего не найдено в базе ФСТЭК."
                    )],
                    structured_content={"query": query, "results": [], "count": 0},
                    meta={"query": query, "limit": limit}
                )
            
            # Форматируем результаты
            formatted_results = []
            text_lines = [f"🔍 Найдено уязвимостей по запросу '{query}': {len(results)}\n"]
            
            for idx, row in results.iterrows():
                vuln_data = {
                    "id": row['Идентификатор'],
                    "name": row['Наименование уязвимости'][:100] + "..." if len(str(row['Наименование уязвимости'])) > 100 else row['Наименование уязвимости'],
                    "severity": row['Уровень опасности уязвимости'],
                    "software": row['Название ПО'],
                    "vendor": row['Вендор ПО']
                }
                formatted_results.append(vuln_data)
                
                text_lines.append(
                    f"📌 **{vuln_data['id']}**\n"
                    f"   Название: {vuln_data['name']}\n"
                    f"   ПО: {vuln_data['vendor']} - {vuln_data['software']}\n"
                    f"   Опасность: {vuln_data['severity']}\n"
                )
            
            await ctx.report_progress(progress=100, total=100)
            await ctx.info(f"✅ Найдено {len(results)} уязвимостей")
            
            span.set_attribute("results_count", len(results))
            span.set_attribute("success", True)
            
            return ToolResult(
                content=[TextContent(type="text", text="\n".join(text_lines))],
                structured_content={
                    "query": query,
                    "results": formatted_results,
                    "count": len(formatted_results)
                },
                meta={"query": query, "limit": limit}
            )
            
        except FileNotFoundError as e:
            span.set_attribute("error", "file_not_found")
            await ctx.error(f"❌ Файл не найден: {e}")
            
            from mcp.shared.exceptions import McpError, ErrorData
            raise McpError(
                ErrorData(
                    code=-32603,
                    message=str(e)
                )
            )
        except Exception as e:
            span.set_attribute("error", str(e))
            await ctx.error(f"❌ Ошибка при поиске: {e}")
            
            from mcp.shared.exceptions import McpError, ErrorData
            raise McpError(
                ErrorData(
                    code=-32603,
                    message=f"Ошибка при поиске уязвимостей: {e}"
                )
            )
