import requests
from typing import List, Dict, Any
import sys
import os

# Добавляем путь для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from scanner.modules.services.base_checker import BaseServiceChecker
from scanner.modules.scanners.web_vulnerability_scanner import WebVulnerabilityScanner


class HTTPChecker(BaseServiceChecker):
    DEFAULT_PORTS = [80, 443, 8080, 8443]
    
    def get_service_payloads(self):
        """HTTP пэйлоады для сбора баннера"""
        return [
            "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
            "OPTIONS / HTTP/1.1\r\nHost: {}\r\n\r\n",
            "HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n"
        ]
    
    def _check_service_specific(self, ports: List[int]) -> Dict[str, Any]:
        """HTTP-специфичные проверки + веб-сканирование"""
        service_info = {
            'http_methods': [],
            'headers': {},
            'server_info': {},
            'redirects': [],
            'status_codes': {},
            'web_vulnerabilities': {}  # Добавляем результаты веб-сканирования
        }
        
        for port in ports:
            try:
                # Определяем протокол по порту
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{self.target_ip}:{port}"
                
                # Проверяем доступность и собираем информацию
                result = self._check_http_endpoint(url, port)
                if result:
                    service_info['http_methods'].extend(result.get('methods', []))
                    service_info['headers'][port] = result.get('headers', {})
                    service_info['server_info'][port] = result.get('server_info', {})
                    service_info['status_codes'][port] = result.get('status_codes', {})
                    
                    # Предлагаем веб-сканирование если сервер отвечает
                    if self._should_offer_web_scan(port, result):
                        if self._ask_for_web_scan(port):
                            web_results = self._run_web_vulnerability_scan(url, port)
                            if web_results:
                                service_info['web_vulnerabilities'][port] = web_results
                    
            except Exception as e:
                self.verbose_print(f'[!] Ошибка проверки HTTP на порту {port}: {e}')
        
        return service_info
    
    def _should_offer_web_scan(self, port: int, http_result: Dict[str, Any]) -> bool:
        """Определяет, стоит ли предлагать веб-сканирование"""
        # Предлагаем если есть успешные HTTP методы
        if http_result.get('methods'):
            return True
        
        # Или если есть серверные заголовки
        if http_result.get('server_info', {}).get('server') not in ['Unknown', '']:
            return True
            
        return False
    
    def _ask_for_web_scan(self, port: int) -> bool:
        """Спрашивает пользователя о запуске веб-сканирования"""
        if not self.is_verbose:
            return False
            
        print(f"\n{'='*50}")
        print(f"[?] Обнаружен веб-сервер на порту {port}")
        print(f"[?] Хотите запустить углубленное веб-сканирование?")
        
        try:
            response = input("1 = да, 0 = нет: ").strip()
            return response == '1'
        except:
            return False
    
    def _run_web_vulnerability_scan(self, url: str, port: int) -> Dict[str, Any]:
        """Запускает веб-сканирование"""
        try:
            self.verbose_print(f"[*] Запуск веб-сканирования: {url}")
            
            scanner = WebVulnerabilityScanner(url, self.is_verbose)
            web_results = scanner.scan_website()
            
            self.verbose_print(f"[+] Веб-сканирование порта {port} завершено")
            return web_results
            
        except Exception as e:
            self.verbose_print(f"[!] Ошибка веб-сканирования: {e}")
            return {}
    
    def _check_http_endpoint(self, url: str, port: int) -> Dict[str, Any]:
        """Проверяет HTTP endpoint и собирает информацию"""
        result = {
            'methods': [],
            'headers': {},
            'server_info': {},
            'status_codes': {}
        }
        
        try:
            # Проверяем основные HTTP методы
            methods_to_check = ['GET', 'OPTIONS', 'HEAD', 'POST']
            
            for method in methods_to_check:
                try:
                    if method == 'GET':
                        response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                    elif method == 'OPTIONS':
                        response = requests.options(url, timeout=5, verify=False)
                    elif method == 'HEAD':
                        response = requests.head(url, timeout=5, verify=False)
                    elif method == 'POST':
                        response = requests.post(url, timeout=5, verify=False, data={'test': 'data'})
                    
                    if response.status_code < 500:  # Игнорируем серверные ошибки
                        result['methods'].append(method)
                        result['status_codes'][method] = response.status_code
                        
                        # Собираем заголовки только для GET
                        if method == 'GET':
                            result['headers'] = dict(response.headers)
                            result['server_info'] = {
                                'server': response.headers.get('Server', 'Unknown'),
                                'content_type': response.headers.get('Content-Type', 'Unknown'),
                                'content_length': response.headers.get('Content-Length', 'Unknown'),
                                'powered_by': response.headers.get('X-Powered-By', 'Unknown')
                            }
                            
                except requests.exceptions.RequestException:
                    continue
            
            self.verbose_print(f'[+] HTTP {port}: доступные методы {result["methods"]}')
            return result
            
        except Exception as e:
            self.verbose_print(f'[-] HTTP {port}: ошибка проверки - {e}')
            return result
    
    def _check_redirects(self, url: str) -> List[str]:
        """Проверяет редиректы"""
        redirects = []
        try:
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            if response.history:
                for resp in response.history:
                    redirects.append({
                        'from': resp.url,
                        'to': resp.headers.get('Location', 'Unknown'),
                        'status': resp.status_code
                    })
        except:
            pass
        return redirects


if __name__ == "__main__":
    TARGET = 'demo-airtickets.local'
    HTTP_PORTS = [80, 443]
    
    checker = HTTPChecker(TARGET)
    print(checker.run(HTTP_PORTS))