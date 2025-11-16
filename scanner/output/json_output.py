import json
from datetime import datetime
from typing import Dict, Any
from scanner.models.scan_results import ScanResults


def save_results(results: ScanResults, filename: str):
    """Сохраняет результаты сканирования в JSON файл"""
    try:
        # Добавляем timestamp
        output_data = results.to_dict()
        output_data['scan_timestamp'] = datetime.now().isoformat()
        output_data['scanner_version'] = 'v2.0'
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        print(f"[!] Ошибка сохранения результатов: {e}")
        return False


def load_results(filename: str) -> Dict[str, Any]:
    """Загружает результаты сканирования из JSON файла"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Ошибка загрузки результатов: {e}")
        return {}