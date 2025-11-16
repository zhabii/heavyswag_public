# scanner/analysis/perplexity_analyzer.py
import json
import requests
from typing import Dict, Any, Optional


class PerplexityAnalyzer:
    """Анализирует результаты сканирования через Perplexity API"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://api.perplexity.ai/chat/completions"
    
    def analyze_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """Анализирует результаты сканирования через Perplexity"""
        
        prompt = self._create_analysis_prompt(scan_results)
        
        try:
            if self.api_key:
                return self._call_perplexity_api(prompt)
            else:
                return self._local_analysis(scan_results)
                
        except Exception as e:
            return f"Ошибка анализа Perplexity: {e}"
    
    def _create_analysis_prompt(self, scan_results: Dict[str, Any]) -> str:
        """Создает промпт для анализа безопасности"""
        
        # Форматируем результаты для лучшей читаемости
        formatted_results = self._format_scan_results(scan_results)
        
        return f"""
        Ты — старший пентестер и эксперт по кибербезопасности. Проанализируй эти результаты сканирования и дай развернутую оценку безопасности.

        РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ХОСТА:
        {formatted_results}

        ПРОАНАЛИЗИРУЙ СЛЕДУЮЩИЕ АСПЕКТЫ:

        1. КРИТИЧЕСКИЕ УЯЗВИМОСТИ 
           - Какие найденные сервисы имеют известные CVE?
           - Есть ли сервисы с устаревшими версиями?
           - Обнаружены ли признаки известных уязвимостей?

        2. СЕТЕВАЯ БЕЗОПАСНОСТЬ
           - Анализ открытых портов и их назначения
           - Оценка конфигурации сетевых сервисов
           - Риски, связанные с конкретными протоколами

        3. ВЕКТОРЫ АТАКИ
           - Какие наиболее вероятные векторы атаки?
           - Какие сервисы требуют немедленного внимания?
           - Возможности для эскалации привилегий

        4. ПРАКТИЧЕСКИЕ РЕКОМЕНДАЦИИ
           - Конкретные шаги по устранению уязвимостей
           - Приоритеты исправлений (Critical, High, Medium, Low)
           - Рекомендации по харденингу

        5. ОБЩАЯ ОЦЕНКА БЕЗОПАСНОСТИ
           - Оценка от 1 до 10 (1 - критически небезопасно, 10 - максимально безопасно)
           - Обоснование оценки

        Ответь на русском языке. Будь конкретен и технически точен. Если есть конкретные версии ПО — укажи известные уязвимости для них.
        """
    
    def _format_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """Форматирует результаты сканирования для лучшей читаемости"""
        formatted = []
        
        # Основная информация
        host = scan_results.get('host', 'N/A')
        formatted.append(f"ЦЕЛЬ: {host}")
        
        # Информация об ОС
        os_info = scan_results.get('os_info', {})
        if os_info:
            os_name = os_info.get('os', 'N/A')
            formatted.append(f"ОПЕРАЦИОННАЯ СИСТЕМА: {os_name}")
            if os_info.get('version'):
                formatted.append(f"ВЕРСИЯ ОС: {os_info['version']}")
        
        # Открытые порты
        open_ports = scan_results.get('open_ports', {})
        tcp_ports = open_ports.get('tcp', [])
        udp_ports = open_ports.get('udp', [])
        
        if tcp_ports:
            formatted.append(f"ОТКРЫТЫЕ TCP ПОРТЫ: {', '.join(map(str, tcp_ports))}")
        if udp_ports:
            formatted.append(f"ОТКРЫТЫЕ UDP ПОРТЫ: {', '.join(map(str, udp_ports))}")
        
        # Сервисы
        services = scan_results.get('services', {})
        if services:
            formatted.append("\nОБНАРУЖЕННЫЕ СЕРВИСЫ:")
            for port, service_info in services.items():
                if isinstance(service_info, dict):
                    service_name = service_info.get('service', 'unknown')
                    formatted.append(f"  Порт {port}: {service_name}")
                    # Уязвимости
                    if 'vulnerabilities' in service_info and service_info['vulnerabilities']:
                        vuln_count = len(service_info['vulnerabilities'])
                        formatted.append(f"    УЯЗВИМОСТИ: {vuln_count} найдено")
                    # Дополнительная информация
                    if 'anonymous_access' in service_info and service_info['anonymous_access']:
                        formatted.append(f"    АНОНИМНЫЙ ДОСТУП: разрешен")
                else:
                    formatted.append(f"  Порт {port}: {service_info}")
        
        # Баннеры
        banners = scan_results.get('banners', {})
        if banners:
            formatted.append("\nСОБРАННЫЕ БАННЕРЫ:")
            for port, banner_data in banners.items():
                banner_text = ""
                
                if isinstance(banner_data, dict):
                    # Если баннер в словаре
                    banner_text = banner_data.get('banner', '')
                else:
                    # Если баннер это строка
                    banner_text = str(banner_data)
                
                if banner_text:
                    # Берем первые 80 символов и убираем переносы строк
                    banner_preview = banner_text.replace('\n', ' ').replace('\r', ' ')[:80]
                    formatted.append(f"  Порт {port}: {banner_preview}...")
        
        # OSINT информация
        osint = scan_results.get('osint', {})
        if osint:
            formatted.append("\nOSINT ИНФОРМАЦИЯ:")
            
            # DNS
            dns_info = osint.get('dns', {})
            if dns_info:
                formatted.append("  DNS:")
                for record_type, values in dns_info.items():
                    if values and isinstance(values, list):
                        formatted.append(f"    {record_type}: {', '.join(values)}")
            
            # WHOIS
            whois_info = osint.get('whois', {})
            if whois_info:
                formatted.append("  WHOIS: данные получены")
        
        return "\n".join(formatted)
    
    def _call_perplexity_api(self, prompt: str) -> str:
        """Вызывает Perplexity API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Актуальные модели из документации Perplexity
        models_to_try = [
            "sonar-pro",  # Рекомендуемая для поиска
            "sonar-medium-online", 
            "sonar-small-chat",
            "sonar-medium-chat",
            "llama-3.1-sonar-small-128k-online",
            "llama-3.1-sonar-medium-128k-online",
            "llama-3.1-sonar-large-128k-online",
            "llama-3.1-sonar-huge-128k-online",
            "mixtral-8x7b-instruct",  # Резервная
            "codellama-70b-instruct"  # Для технических вопросов
        ]
        
        for model in models_to_try:
            try:
                data = {
                    "model": model,
                    "messages": [
                        {
                            "role": "system", 
                            "content": "Ты эксперт по кибербезопасности. Анализируй результаты сканирования сетей и сервисов."
                        },
                        {
                            "role": "user", 
                            "content": prompt
                        }
                    ],
                    "max_tokens": 2000,
                    "temperature": 0.1,
                    "top_p": 0.9,
                    "stream": False
                }
                
                print(f"Пробуем модель: {model}")
                response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    return result["choices"][0]["message"]["content"]
                elif response.status_code == 400:
                    error_info = response.json()
                    error_msg = error_info.get('error', {}).get('message', '')
                    if 'model' in error_msg.lower():
                        continue  # Пробуем следующую модель
                    else:
                        return f"Ошибка API: {error_msg}"
                else:
                    continue  # Пробуем следующую модель
                    
            except Exception as e:
                continue
        
        return "Не удалось подключиться ни к одной модели. Проверь доступные модели в документации."
    
    def _local_analysis(self, scan_results: Dict[str, Any]) -> str:
        """Локальный анализ без API (fallback)"""
        return """
🔍 АНАЛИЗ БЕЗОПАСНОСТИ (Локальная оценка)

Perplexity API ключ не указан. Для получения детального AI-анализа:

1. Получи API ключ на https://www.perplexity.ai/
2. Используй: analyzer.analyze_with_perplexity(api_key="your-key")

БАЗОВАЯ ОЦЕНКА:
- Проанализируйте открытые порты на предмет известных уязвимостей
- Проверьте версии сервисов на наличие CVE
- Убедитесь, что не используются дефолтные учетные данные
- Закройте неиспользуемые порты

💡 ДЛЯ ДЕТАЛЬНОГО АНАЛИЗА ИСПОЛЬЗУЙТЕ PERPLEXITY API
"""