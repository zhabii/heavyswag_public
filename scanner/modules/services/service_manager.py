from typing import Dict, List, Any, Optional

from scanner.utils.verbose_mixin import VerboseMixin
from scanner.modules.scanners.banner_grubber import BannerGrubber
from scanner.modules.services.ftp_checker import FTPChecker
from scanner.modules.services.http_checker import HTTPChecker
from scanner.modules.services.snmp_checker import SNMPChecker

from scanner.utils.cve_mixin import CVEMixin

class ServiceManager(VerboseMixin, CVEMixin):
    def __init__(self, host: str, verbose: bool = True):
        self.host = host
        self.is_verbose = verbose

        # Простые обработчики
        self.service_handlers = {
            21: self._check_ftp,
            80: self._check_http,
            443: self._check_http,
            8080: self._check_http,
            8443: self._check_http,
            161: self._check_snmp,
        }

    def process_ports(self, open_ports: Dict[str, List[int]]) -> Dict[str, Any]:
        """Обрабатывает открытые порты - возвращает {'services': {}, 'banners': {}}"""
        services = {}
        banners = {}

        for protocol, ports in open_ports.items():
            self.verbose_print(f"[*] Обработка {protocol.upper()} портов: {ports}")
            
            for port in ports:
                # Пробуем снять баннер
                banner = self._grab_banner(port, protocol)
                if banner:
                    banners[port] = banner

                # Проверяем специальные сервисы
                if port in self.service_handlers:
                    service_data = self.service_handlers[port](port, protocol)
                    services[port] = {"protocol": protocol, "service": service_data}
                    self.verbose_print(f"[+] Обработан сервис {protocol.upper()}/{port}")
                else:
                    self.verbose_print(f"[-] {protocol.upper()}/{port}: нет специального обработчика")

        return {"services": services, "banners": banners}

    def _check_ftp(self, port: int, protocol: str) -> Dict[str, Any]:
        """Проверяет FTP"""
        try:
            checker = FTPChecker(self.host, self.is_verbose)
            return checker.run([port])
        except Exception as e:
            self.verbose_print(f"[!] Ошибка проверки FTP {port}: {e}")
            return {"service": "ftp", "error": str(e)}

    def _check_http(self, port: int, protocol: str) -> Dict[str, Any]:
        """Проверяет HTTP"""
        try:
            checker = HTTPChecker(self.host, self.is_verbose)
            return checker.run([port])
        except Exception as e:
            self.verbose_print(f"[!] Ошибка проверки HTTP {port}: {e}")
            return {"service": "http", "error": str(e)}
        
        
    def _check_snmp(self, port: int, protocol: str) -> Dict[str, Any]:
        """Проверяет SNMP"""
        try:
            checker = SNMPChecker(self.host, self.is_verbose)
            return checker.run([port])
        except Exception as e:
            self.verbose_print(f"[!] Ошибка проверки SNMP {port}: {e}")
            return {"service": "snmp", "error": str(e)}

    def _grab_banner(self, port: int, protocol: str) -> Optional[str]:
        """Пытается снять баннер"""
        try:
            grabber = BannerGrubber(
                self.host,
                tcp_ports=[port] if protocol == "tcp" else [],
                udp_ports=[port] if protocol == "udp" else [],
                verbose=self.is_verbose,
            )
            result = grabber.start()
            if result and port in result:
                banner = result[port].get("banner")
                if banner:
                    self.verbose_print(f"[+] Баннер {protocol.upper()}/{port}: {banner[:100]}...")
                    cve_results = self.search_CVEs(banner)
                    if cve_results:
                        return {banner: cve_results}
                return banner
            return None
        except Exception as e:
            self.verbose_print(f"[!] Ошибка снятия баннера {port}: {e}")
            return None