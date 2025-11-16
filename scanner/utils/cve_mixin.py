import nvdlib
import sys
import os

# Добавляем путь для импортов (если нужно импортировать другие утилиты)
sys.path.append(os.path.dirname(__file__))

from verbose_mixin import VerboseMixin  # Импортируем базовый миксин


class CVEMixin(VerboseMixin):  # Наследуем от VerboseMixin для consistency
    def search_CVEs(self, keyword: str, limit: int = 5):  # Добавил self
        """
        Ищет данные в NVD по ключевому слову и возвращает словарь
        формата {cve: id, published: date, severity: severity: url: url} 
        """
        self.verbose_print(f"[*] Поиск CVE по ключевому слову: '{keyword}'")
        
        try:
            cves = nvdlib.searchCVE_V2(keywordSearch=keyword, limit=limit)
        except Exception as e:
            self.verbose_print(f'[!] Ошибка при поиске CVE: {e}')
            return []
            
        result = []
        for cve in cves:
            cve_data = {
                "cve": getattr(cve, "id", "N/A"),
                "published": getattr(cve, "published", "N/A"),
                "severity": getattr(cve, "v2severity", "N/A"),
                "url": getattr(cve, "url", "N/A"),
            }
            result.append(cve_data)
            
        self.verbose_print(f"[+] Найдено {len(result)} CVE записей")
        return result