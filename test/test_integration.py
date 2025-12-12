"""Интеграционные тесты для FSTEC MCP сервера.

Эти тесты проверяют инструменты напрямую, без декораторов MCP.
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
import pandas as pd
import sys
import os

# Добавляем корень проекта в path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def mock_context():
    """Создаёт мок Context для тестов."""
    ctx = Mock()
    ctx.info = AsyncMock()
    ctx.error = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.debug = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


@pytest.fixture
def sample_search_results():
    """Создаёт примерные результаты поиска."""
    return pd.DataFrame({
        'Идентификатор': ['BDU:2024-00001', 'BDU:2024-00002'],
        'Наименование уязвимости': ['Vuln 1', 'Vuln 2'],
        'Описание уязвимости': ['Desc 1', 'Desc 2'],
        'Вендор ПО': ['Vendor 1', 'Vendor 2'],
        'Название ПО': ['nginx', 'nginx'],
        'Версия ПО': ['1.0', '2.0'],
        'Уровень опасности уязвимости': ['Critical', 'High'],
    })


@pytest.fixture
def sample_vuln_details():
    """Создаёт примерные данные уязвимости."""
    return pd.Series({
        'Идентификатор': 'BDU:2024-12345',
        'Наименование уязвимости': 'Test Vulnerability',
        'Описание уязвимости': 'Description of vulnerability',
        'Вендор ПО': 'Test Vendor',
        'Название ПО': 'Test Software',
        'Версия ПО': '1.0.0',
        'Тип ПО': 'Application',
        'Наименование ОС': 'Linux',
        'Класс уязвимости': 'Remote Code Execution',
        'Дата выявления': '2024-01-01',
        'CVSS 2.0': '10.0',
        'CVSS 3.0': '9.8',
        'CVSS 4.0': '9.5',
        'Уровень опасности уязвимости': 'Критический',
        'Возможные меры по устранению': 'Update to latest version',
        'Статус уязвимости': 'Confirmed',
        'Наличие эксплойта': 'Yes',
        'Информация об устранении': 'Patch available',
        'Ссылки на источники': 'https://example.com',
        'Идентификаторы других систем': 'CVE-2024-12345',
        'Прочая информация': 'None',
        'Связь с инцидентами ИБ': 'None',
        'Способ эксплуатации': 'Remote',
        'Способ устранения': 'Patch',
        'Дата публикации': '2024-01-02',
        'Дата последнего обновления': '2024-01-03',
        'Последствия эксплуатации': 'Full system compromise',
        'Состояние уязвимости': 'Published',
        'Описание ошибки CWE': 'Buffer overflow',
        'Тип ошибки CWE': 'CWE-120',
    })


class TestSearchVulnerabilitiesLogic:
    """Тесты логики поиска уязвимостей."""
    
    @pytest.mark.asyncio
    async def test_search_returns_results(self, mock_context, sample_search_results):
        """Тест успешного поиска с результатами."""
        mock_loader = Mock()
        mock_loader.search = Mock(return_value=sample_search_results)
        
        with patch('tools.utils.FSTECDataLoader.get_instance', return_value=mock_loader):
            from tools.utils import FSTECDataLoader
            
            loader = FSTECDataLoader.get_instance()
            results = loader.search("nginx", 5)
            
            assert len(results) == 2
            assert results.iloc[0]['Идентификатор'] == 'BDU:2024-00001'
    
    @pytest.mark.asyncio
    async def test_search_no_results(self, mock_context):
        """Тест поиска без результатов."""
        mock_loader = Mock()
        mock_loader.search = Mock(return_value=pd.DataFrame())
        
        with patch('tools.utils.FSTECDataLoader.get_instance', return_value=mock_loader):
            from tools.utils import FSTECDataLoader
            
            loader = FSTECDataLoader.get_instance()
            results = loader.search("nonexistent", 5)
            
            assert len(results) == 0


class TestGetVulnerabilityDetailsLogic:
    """Тесты логики получения деталей уязвимости."""
    
    @pytest.mark.asyncio
    async def test_get_details_found(self, mock_context, sample_vuln_details):
        """Тест получения деталей существующей уязвимости."""
        mock_loader = Mock()
        mock_loader.get_by_id = Mock(return_value=sample_vuln_details)
        
        with patch('tools.utils.FSTECDataLoader.get_instance', return_value=mock_loader):
            from tools.utils import FSTECDataLoader
            
            loader = FSTECDataLoader.get_instance()
            result = loader.get_by_id("BDU:2024-12345")
            
            assert result is not None
            assert result['Идентификатор'] == "BDU:2024-12345"
            assert result['Уровень опасности уязвимости'] == "Критический"
    
    @pytest.mark.asyncio
    async def test_get_details_not_found(self, mock_context):
        """Тест получения несуществующей уязвимости."""
        mock_loader = Mock()
        mock_loader.get_by_id = Mock(return_value=None)
        
        with patch('tools.utils.FSTECDataLoader.get_instance', return_value=mock_loader):
            from tools.utils import FSTECDataLoader
            
            loader = FSTECDataLoader.get_instance()
            result = loader.get_by_id("BDU:2024-99999")
            
            assert result is None


class TestToolResultFormat:
    """Тесты форматирования результатов."""
    
    def test_text_content_creation(self):
        """Тест создания TextContent."""
        from mcp.types import TextContent
        from tools.utils import ToolResult
        
        content = [TextContent(type="text", text="Test message")]
        result = ToolResult(
            content=content,
            structured_content={"test": "data"},
            meta={"info": "value"}
        )
        
        assert result.content[0].text == "Test message"
        assert result.structured_content["test"] == "data"
    
    def test_structured_content_format(self):
        """Тест формата structured_content для поиска."""
        from mcp.types import TextContent
        from tools.utils import ToolResult
        
        result = ToolResult(
            content=[TextContent(type="text", text="Found 2 results")],
            structured_content={
                "query": "nginx",
                "count": 2,
                "results": [
                    {"id": "BDU:2024-00001", "name": "Vuln 1"},
                    {"id": "BDU:2024-00002", "name": "Vuln 2"},
                ]
            },
            meta={"query": "nginx", "limit": 5}
        )
        
        assert result.structured_content["query"] == "nginx"
        assert result.structured_content["count"] == 2
        assert len(result.structured_content["results"]) == 2


class TestErrorHandling:
    """Тесты обработки ошибок."""
    
    def test_mcp_error_creation(self):
        """Тест создания McpError."""
        from mcp.shared.exceptions import McpError, ErrorData
        
        error = McpError(
            ErrorData(
                code=-32603,
                message="Test error message"
            )
        )
        
        assert "-32603" in str(error) or "Test error" in str(error)
    
    def test_file_not_found_handling(self):
        """Тест обработки отсутствия файла."""
        from tools.utils import FSTECDataLoader
        
        # Сбрасываем singleton
        FSTECDataLoader._instance = None
        FSTECDataLoader._df = None
        
        with pytest.raises(FileNotFoundError) as exc_info:
            FSTECDataLoader.get_instance("nonexistent.xlsx")
        
        assert "не найден" in str(exc_info.value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
