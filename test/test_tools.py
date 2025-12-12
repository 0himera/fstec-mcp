"""Unit тесты для инструментов FSTEC MCP сервера.

Тесты используют моки и фикстуры для изоляции от реальных данных.
"""
import pytest
import pandas as pd
from unittest.mock import Mock, patch, PropertyMock
import sys
import os

# Добавляем корень проекта в path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sample_dataframe():
    """Создаёт тестовый DataFrame для FSTECDataLoader."""
    return pd.DataFrame({
        'Идентификатор': ['BDU:2024-00001', 'BDU:2024-00002', 'BDU:2024-00003'],
        'Наименование уязвимости': ['Nginx vuln 1', 'Nginx vuln 2', 'Apache vuln'],
        'Описание уязвимости': ['Buffer overflow', 'XSS attack', 'SQL injection'],
        'Вендор ПО': ['nginx Inc', 'nginx Inc', 'Apache Foundation'],
        'Название ПО': ['nginx', 'nginx', 'apache'],
        'Версия ПО': ['1.5.6', '2.0.0', '2.4.0'],
        'Тип ПО': ['Веб-сервер', 'Веб-сервер', 'Веб-сервер'],
        'Наименование ОС': ['Linux', 'Linux', 'Linux'],
        'Класс уязвимости': ['RCE', 'XSS', 'SQLi'],
        'Дата выявления': ['2024-01-01', '2024-02-01', '2024-03-01'],
        'CVSS 2.0': ['10.0', '5.0', '7.5'],
        'CVSS 3.0': ['9.8', '4.3', '8.1'],
        'CVSS 4.0': ['9.5', '4.0', '7.8'],
        'Уровень опасности уязвимости': ['Критический', 'Средний', 'Высокий'],
        'Возможные меры по устранению': ['Update', 'Patch', 'Configure'],
        'Статус уязвимости': ['Confirmed', 'Confirmed', 'Confirmed'],
        'Наличие эксплойта': ['Да', 'Нет', 'Да'],
        'Информация об устранении': ['Fixed', 'Fixed', 'Fixed'],
        'Ссылки на источники': ['http://a', 'http://b', 'http://c'],
        'Идентификаторы других систем': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],
        'Прочая информация': ['None', 'None', 'None'],
        'Связь с инцидентами ИБ': ['None', 'None', 'None'],
        'Способ эксплуатации': ['Remote', 'Remote', 'Remote'],
        'Способ устранения': ['Patch', 'Patch', 'Patch'],
        'Дата публикации': ['2024-01-02', '2024-02-02', '2024-03-02'],
        'Дата последнего обновления': ['2024-01-03', '2024-02-03', '2024-03-03'],
        'Последствия эксплуатации': ['Compromise', 'Data leak', 'Data leak'],
        'Состояние уязвимости': ['Published', 'Published', 'Published'],
        'Описание ошибки CWE': ['CWE-120', 'CWE-79', 'CWE-89'],
        'Тип ошибки CWE': ['Buffer overflow', 'XSS', 'SQLi'],
    })


class TestFSTECDataLoaderSearch:
    """Тесты поиска в FSTECDataLoader."""
    
    def test_search_single_word(self, sample_dataframe):
        """Тест поиска по одному слову."""
        from tools.utils import FSTECDataLoader
        
        # Создаём экземпляр без загрузки файла
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("nginx", limit=10)
        
        assert len(results) == 2
    
    def test_search_multiple_words(self, sample_dataframe):
        """Тест поиска по нескольким словам (AND логика)."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("nginx 1.5.6", limit=10)
        
        assert len(results) == 1
        assert results.iloc[0]['Идентификатор'] == 'BDU:2024-00001'
    
    def test_search_case_insensitive(self, sample_dataframe):
        """Тест регистронезависимого поиска."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("NGINX", limit=10)
        
        assert len(results) == 2
    
    def test_search_empty_query(self, sample_dataframe):
        """Тест поиска с пустым запросом."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("", limit=10)
        
        assert len(results) == 0
    
    def test_search_limit(self, sample_dataframe):
        """Тест ограничения количества результатов."""
        from tools.utils import FSTECDataLoader
        
        # Добавляем больше записей nginx
        extended_df = pd.concat([sample_dataframe] * 5, ignore_index=True)
        
        loader = FSTECDataLoader()
        loader._df = extended_df
        
        results = loader.search("nginx", limit=3)
        
        assert len(results) == 3
    
    def test_search_in_description(self, sample_dataframe):
        """Тест поиска в описании уязвимости."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("buffer overflow", limit=10)
        
        assert len(results) == 1
        assert results.iloc[0]['Идентификатор'] == 'BDU:2024-00001'
    
    def test_search_in_vendor(self, sample_dataframe):
        """Тест поиска по вендору."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("Apache Foundation", limit=10)
        
        assert len(results) == 1
    
    def test_search_no_results(self, sample_dataframe):
        """Тест поиска без результатов."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        results = loader.search("nonexistent_software_xyz", limit=10)
        
        assert len(results) == 0


class TestFSTECDataLoaderGetById:
    """Тесты получения по ID в FSTECDataLoader."""
    
    def test_get_by_id_found(self, sample_dataframe):
        """Тест получения уязвимости по ID - найдена."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        result = loader.get_by_id("BDU:2024-00001")
        
        assert result is not None
        assert result['Идентификатор'] == 'BDU:2024-00001'
        assert result['Уровень опасности уязвимости'] == 'Критический'
    
    def test_get_by_id_not_found(self, sample_dataframe):
        """Тест получения уязвимости по ID - не найдена."""
        from tools.utils import FSTECDataLoader
        
        loader = FSTECDataLoader()
        loader._df = sample_dataframe
        
        result = loader.get_by_id("BDU:2024-99999")
        
        assert result is None


class TestFSTECDataLoaderSingleton:
    """Тесты паттерна singleton."""
    
    def setup_method(self):
        """Сброс singleton перед каждым тестом."""
        from tools.utils import FSTECDataLoader
        FSTECDataLoader._instance = None
        FSTECDataLoader._df = None
    
    def test_file_not_found(self):
        """Проверка ошибки при отсутствии файла."""
        from tools.utils import FSTECDataLoader
        
        with pytest.raises(FileNotFoundError) as exc_info:
            FSTECDataLoader.get_instance("nonexistent_file.xlsx")
        
        assert "не найден" in str(exc_info.value)


class TestToolResult:
    """Тесты для класса ToolResult."""
    
    def test_tool_result_creation(self):
        """Тест создания ToolResult."""
        from mcp.types import TextContent
        from tools.utils import ToolResult
        
        result = ToolResult(
            content=[TextContent(type="text", text="Test")],
            structured_content={"key": "value"},
            meta={"info": "test"}
        )
        
        assert len(result.content) == 1
        assert result.content[0].text == "Test"
        assert result.structured_content["key"] == "value"
        assert result.meta["info"] == "test"


class TestRequireEnvVars:
    """Тесты для функции _require_env_vars."""
    
    def test_all_vars_present(self, monkeypatch):
        """Тест когда все переменные присутствуют."""
        from tools.utils import _require_env_vars
        
        monkeypatch.setenv("TEST_VAR1", "value1")
        monkeypatch.setenv("TEST_VAR2", "value2")
        
        result = _require_env_vars(["TEST_VAR1", "TEST_VAR2"])
        
        assert result["TEST_VAR1"] == "value1"
        assert result["TEST_VAR2"] == "value2"
    
    def test_missing_vars(self, monkeypatch):
        """Тест когда переменные отсутствуют."""
        from mcp.shared.exceptions import McpError
        from tools.utils import _require_env_vars
        
        monkeypatch.delenv("MISSING_VAR", raising=False)
        
        with pytest.raises(McpError):
            _require_env_vars(["MISSING_VAR"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
