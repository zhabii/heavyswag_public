from typing import Dict, List, Any, Optional
import textwrap as tw
from scanner.utils.verbose_mixin import VerboseMixin
from scanner.models.scan_results import ScanResults

# Абсолютные импорты
from scanner.modules.osint.dns_lookup import DNSLookup
from scanner.modules.osint.whois_lookup import WhoisLookup
from scanner.modules.scanners.os_fingerprint import OSFingerprint
from scanner.modules.scanners.port_scanner import PortScanner
from scanner.modules.scanners.banner_grubber import BannerGrubber
from scanner.modules.services.service_manager import ServiceManager
from scanner.analysis.perplexity_analyzer import PerplexityAnalyzer


banner = tw.dedent(r"""________________________ __________     __________ __ _________________     _________________________________________________
 /$$                                                                                                 
| $$                                                                                                 
| $$$$$$$   /$$$$$$   /$$$$$$  /$$    /$$ /$$   /$$        /$$$$$$$ /$$  /$$  /$$  /$$$$$$   /$$$$$$ 
| $$__  $$ /$$__  $$ |____  $$|  $$  /$$/| $$  | $$       /$$_____/| $$ | $$ | $$ |____  $$ /$$__  $$
| $$  \ $$| $$$$$$$$  /$$$$$$$ \  $$/$$/ | $$  | $$      |  $$$$$$ | $$ | $$ | $$  /$$$$$$$| $$  \ $$
| $$  | $$| $$_____/ /$$__  $$  \  $$$/  | $$  | $$       \____  $$| $$ | $$ | $$ /$$__  $$| $$  | $$
| $$  | $$|  $$$$$$$|  $$$$$$$   \  $/   |  $$$$$$$       /$$$$$$$/|  $$$$$/$$$$/|  $$$$$$$|  $$$$$$$
|__/  |__/ \_______/ \_______/    \_/     \____  $$      |_______/  \_____/\___/  \_______/ \____  $$
                                          /$$  | $$                                         /$$  \ $$
                                         |  $$$$$$/                                        |  $$$$$$/
                                          \______/                                          \______/ """)


class Orchestrator(VerboseMixin):
    """Соединяет все модули в одно сканирование"""

    def __init__(self, host: str, is_verbose: bool = True):
        self.host = host
        self.is_verbose = is_verbose
        self.results = ScanResults(host=host)  # модель данных

    def scan_host(self) -> ScanResults:
        """Точка начала сканирования хоста"""
        
        self.verbose_print(banner)
        self.verbose_print(f"[*] СТАРТ СКАНИРОВАНИЯ {self.host}...")

        try:
            # 1. Пассивная разведка (whois, DNS)
            self._run_osint()

            # 2. OS Fingerprinting
            self._run_os_fingerprint()

            # 3. Сканирование портов
            open_ports = self._run_port_scanning()
            self.results.open_ports = open_ports

            # 4. Анализ и обработка портов
            self._process_ports(open_ports)

            return self.results

        except Exception as e:
            self.verbose_print(f"[!] Ошибка сканирования: {e}")
            return self.results

    def _run_osint(self):
        """Запускает OSINT модули"""
        self.verbose_print("\n[=== OSINT РАЗВЕДКА ===]")

        # DNS lookup
        try:
            dns = DNSLookup(self.is_verbose)
            dns_results = dns.lookup(self.host)
            self.results.osint["dns"] = dns_results
        except Exception as e:
            self.verbose_print(f"[!] Ошибка DNS lookup: {e}")

        # WHOIS lookup
        try:
            whois = WhoisLookup(self.is_verbose)
            whois_results = whois.lookup(self.host)
            self.results.osint["whois"] = whois_results
        except Exception as e:
            self.verbose_print(f"[!] Ошибка WHOIS lookup: {e}")

    def _run_os_fingerprint(self):
        """Запускает OS Fingerprint модули"""
        print("\n[=== oS FINGERPRINTING ===]")

        try:
            os_fp = OSFingerprint()
            os_info = os_fp.detect(self.host)
            self.results.os_info = os_info
            print(self.results.os_info)
        except Exception as e:
            self.verbose_print(f"[!] Ошибка OS fingerprinting: {e}")

    def _run_port_scanning(self):
        """Запускает комплексное сканирование портов"""
        self.verbose_print("\n[=== СКАНИРОВАНИЕ ПОРТОВ ===]")

        # Конфигурации сканирования
        scan_configs = [
            {"scan_type": "syn", "ports": list(range(1, 1001))},
            {
                "scan_type": "udp",
                "ports": [
                    53,
                    67,
                    68,
                    69,
                    123,
                    135,
                    137,
                    138,
                    139,
                    161,
                    162,
                    445,
                    514,
                    520,
                    631,
                    1434,
                    1900,
                    4500,
                    49152,
                ],
            },
        ]

        all_results = {"tcp": [], "udp": []}

        for config in scan_configs:
            try:
                scanner = PortScanner(
                    target_ip=self.host,
                    target_ports=config["ports"],
                    mode=config["scan_type"],
                    is_verbose=False,  # пока так
                    threads=10,
                    timeout=2,
                )
                open_ports = scanner.scan()

                # Нормализуем тип сканирования
                scan_type = "tcp" if config["scan_type"] in ["syn", "tcp"] else "udp"
                all_results[scan_type].extend(open_ports)

            except Exception as e:
                self.verbose_print(
                    f"[!] Ошибка {config['scan_type']} сканирования: {e}"
                )

        # Сортируем и убираем дубликаты
        all_results["tcp"] = sorted(set(all_results["tcp"]))
        all_results["udp"] = sorted(set(all_results["udp"]))

        self.verbose_print(f"[+] Найдено TCP портов: {len(all_results['tcp'])}")
        self.verbose_print(f"[+] Найдено UDP портов: {len(all_results['udp'])}")

        return all_results

    def _process_ports(self, open_ports: Dict[str, List[int]]):
        """Обрабатывает найденные порты"""
        self.verbose_print("\n[=== АНАЛИЗ СЕРВИСОВ ===]")

        try:
            # Используем ServiceManager для обработки портов
            service_manager = ServiceManager(self.host, self.is_verbose)
            service_results = service_manager.process_ports(open_ports)

            # Сохраняем результаты
            self.results.services = service_results["services"]
            self.results.banners = service_results["banners"]

            self.verbose_print(f"[+] Обработано сервисов: {len(self.results.services)}")
            self.verbose_print(f"[+] Собрано баннеров: {len(self.results.banners)}")

        except Exception as e:
            self.verbose_print(f"[!] Ошибка обработки портов: {e}")

    def print_summary(self):
        """Печатает краткую сводку сканирования"""
        print(f"\n{'='*60}")
        print(f"СВОДКА СКАНИРОВАНИЯ: {self.host}")
        print(f"{'='*60}")

        # OS информация
        if self.results.os_info:
            print(f"ОС: {self.results.os_info.get('os', 'Не определено')}")

        # Порты
        tcp_ports = len(self.results.open_ports.get("tcp", []))
        udp_ports = len(self.results.open_ports.get("udp", []))
        print(f"Открытые порты: TCP={tcp_ports}, UDP={udp_ports}")

        # Сервисы
        print(f"Обнаружено сервисов: {len(self.results.services)}")
        print(f"Собрано баннеров: {len(self.results.banners)}")

        # DNS информация
        if self.results.osint.get("dns"):
            dns_info = self.results.osint["dns"]
            if "PTR" in dns_info:
                print(f"DNS PTR: {dns_info['PTR']}")

        print(f"{'='*60}")

    def analyze_with_perplexity(self, api_key: str = None):
        """Анализирует результаты через Perplexity API"""
        print(f"\n{'='*60}")
        print("PERPLEXITY AI АНАЛИЗ БЕЗОПАСНОСТИ")
        print(f"{'='*60}")

        analyzer = PerplexityAnalyzer(api_key=api_key)
        analysis = analyzer.analyze_scan_results(self.results.to_dict())

        print(analysis)
        print(f"{'='*60}")


if __name__ == "__main__":
    # Тестирование
    TARGET = "127.0.0.1"

    orch = Orchestrator(TARGET, is_verbose=True)
    results = orch.scan_host()

    # Печатаем сводку
    orch.print_summary()

    # Perplexity AI анализ
    # orch.analyze_with_perplexity(api_key="")  # Без ключа - инструкция

    # Детальные результаты
    import pprint

    print("\nДетальные результаты:")
    pprint.pprint(results.to_dict())
