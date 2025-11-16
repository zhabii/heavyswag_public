from abc import ABC, abstractmethod
from typing import List, Dict, Any
import re
from scanner.utils.verbose_mixin import VerboseMixin
from scanner.utils.cve_mixin import CVEMixin
from scanner.modules.scanners.banner_grubber import BannerGrubber

class BaseServiceChecker(ABC, VerboseMixin, CVEMixin):
    """Базовый класс для всех сервис-чекеров"""
    
    # Порт по умолчанию для сервиса
    DEFAULT_PORTS = []
    
    def __init__(self, host: str, is_verbose: bool = True):
        self.target_ip = host
        self.is_verbose = is_verbose
        self.banner_grubber = BannerGrubber(host, verbose=is_verbose)

    @classmethod
    def get_default_ports(cls) -> List[int]:
        """Возвращает дефолтные порты для этого сервиса"""
        return cls.DEFAULT_PORTS

    @abstractmethod
    def get_service_payloads(self) -> List[str]:
        """Вернуть специфичные пэйлоады для сервиса"""
        pass

    def run(self, ports: List[int] = None, custom_payloads: List[str] = None) -> Dict[str, Any]:
        """Основной метод запуска проверки сервиса"""
        # Если порты не передаются, до сканируются дефолтные для сервиса
        if ports is None:
            ports = self.get_default_ports()
        
        payloads = custom_payloads or self.get_service_payloads()
        
        result = {
            'service': self.__class__.__name__.replace('Checker', '').lower(),
            'ports': ports,
            'banners': {},
            'vulnerabilities': [],
            'service_info': {}
        }
        
        # 1. Сбор баннеров
        result['banners'] = self._grab_banners(ports, payloads)
        
        # 2. Проверка специфичной логики сервиса
        result['service_info'] = self._check_service_specific(ports)
        
        # 3. Поиск уязвимостей - просто ищет по банерам
        result['vulnerabilities'] = self._check_vulnerabilities(result['banners'])
        
        return result

    def _grab_banners(self, ports: List[int], payloads: List[str]) -> Dict[int, str]:
        """Сбор баннеров с портов"""
        self.banner_grubber.tcp_ports = ports
        banners_result = self.banner_grubber.start(payloads=payloads)
        
        # Нормализуем результат
        normalized = {}
        for port, banner_data in banners_result.items():
            normalized[port] = banner_data.get('banner', '')
        
        return normalized

    @abstractmethod
    def _check_service_specific(self, ports: List[int]) -> Dict[str, Any]:
        """Специфичная проверка сервиса"""
        pass

    def _check_vulnerabilities(self, banners: Dict[int, str]) -> List[Dict[str, Any]]:
        """Базовая проверка уязвимостей через CVE миксин"""
        vulnerabilities = []
        
        for port, banner in banners.items():

            if banner:
                self.verbose_print(f"[*] Анализ баннера порта {port}: {banner[:100]}...")
                search_terms = self._extract_search_terms_from_banner(banner)
                
                if search_terms:
                    self.verbose_print(f"[*] Извлечены термины для поиска: {search_terms}")
                else:
                    self.verbose_print("[-] Не найдено релевантных терминов для поиска CVE")
                    continue
                
                for term in search_terms:
                    self.verbose_print(f"[*] Поиск CVE для: '{term}'")
                    cve_results = self.search_CVEs(term)
                    if cve_results:
                        vulnerabilities.extend(cve_results)
                        self.verbose_print(f"[+] Найдено {len(cve_results)} CVE для '{term}'")

        
        return vulnerabilities

    def _extract_search_terms_from_banner(self, banner: str) -> List[str]:
        """Извлекает ключевые слова для поиска CVE из баннера"""
        import re
        search_terms = []
        
        # Строгий список игнорируемых слов
        IGNORE_WORDS = {
            # HTTP заголовки
            'http', 'https', 'server', 'date', 'content', 'type', 'length', 
            'connection', 'location', 'cache', 'control', 'accept', 'encoding',
            'language', 'user', 'agent', 'host', 'referer', 'cookie', 'set',
            'allow', 'etag', 'last', 'modified', 'expires', 'pragma', 'range',
            'via', 'warning', 'www', 'authenticate', 'authorization',
            
            # Общие слова
            'version', 'ready', 'welcome', 'connected', 'open', 'forbidden',
            'not', 'found', 'error', 'success', 'ok', 'failed', 'denied',
            'unauthorized', 'internal', 'bad', 'request', 'service', 'unavailable',
            
            # Временные слова
            'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun', 'jan', 'feb', 'mar',
            'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
            
            # Протоколы
            'tcp', 'udp', 'ssl', 'tls', 'ftp', 'ssh', 'smtp', 'dns', 'snmp',
            
            # Прочее
            'the', 'and', 'for', 'with', 'this', 'that', 'from', 'have'
        }
        
        # 1. Ищем содержимое в скобках - самый важный паттерн
        bracket_matches = re.findall(r'\(([^)]+)\)', banner)
        for match in bracket_matches:
            cleaned = ' '.join(match.split())
            if (cleaned and 
                len(cleaned) > 3 and 
                not any(word in cleaned.lower() for word in ['welcome', 'ready', 'server'])):
                search_terms.append(cleaned)
        
        # 2. Ищем ПО с версиями (nginx/1.24.0, Apache 2.4.41)
        version_patterns = [
            r'([A-Za-z]+(?:[-\w]+)?)\s*[/\s-]*v?([\d.]+[a-z]?\d*)',  # "nginx/1.24.0" или "Apache 2.4.41"
            r'([A-Z][a-z]+[A-Za-z]*)\s+([\d.]+[a-z]?\d*)',  # "ProFTPD 1.3.3c"
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, banner)
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    software = match[0].strip()
                    version = match[1].strip()
                    
                    # Фильтруем мусор
                    if (software.lower() not in IGNORE_WORDS and
                        len(software) > 2 and
                        not version.startswith('1.1') and  # Игнорируем HTTP/1.1
                        not re.match(r'^\d{1,2}:\d{2}:\d{2}', version)):  # Игнорируем время
                        
                        term = f"{software} {version}"
                        if term not in search_terms:
                            search_terms.append(term)
        
        # 3. Ищем только известные названия ПО (строгий список)
        KNOWN_SOFTWARE = {
            'nginx', 'apache', 'httpd', 'iis', 'tomcat', 'jetty',
            'proftpd', 'vsftpd', 'pure-ftpd', 'filezilla',
            'openssh', 'dropbear', 'putty',
            'bind', 'powerdns', 'unbound',
            'mysql', 'mariadb', 'postgresql', 'mongodb', 'redis',
            'wordpress', 'joomla', 'drupal', 'magento',
            'ubuntu', 'debian', 'centos', 'redhat', 'windows'
        }
        
        software_matches = re.findall(r'\b([A-Z][a-z]+(?:[-\w]+)?)\b', banner)
        for software in software_matches:
            software_lower = software.lower()
            if (software_lower in KNOWN_SOFTWARE and 
                software not in search_terms and
                not any(term.startswith(software) for term in search_terms)):
                search_terms.append(software)
        
        # 4. Фильтруем результаты
        filtered_terms = []
        for term in search_terms:
            term_lower = term.lower()
            
            # Пропускаем если содержит игнорируемые слова
            if any(ignore_word in term_lower for ignore_word in IGNORE_WORDS):
                continue
                
            # Пропускаем даты и временные метки
            if re.search(r'\b(20\d{2}|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b', term_lower):
                continue
                
            # Пропускаем HTTP версии
            if re.search(r'http/\d\.\d', term_lower):
                continue
                
            filtered_terms.append(term)
        
        return filtered_terms