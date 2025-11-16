from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class ScanResults:
    host: str
    open_ports: Dict[str, List[int]] = field(
        default_factory=dict
    )  # {'tcp': [80, 443], 'udp': [53]}
    os_info: Dict[str, Any] = field(
        default_factory=dict
    )  # {'method': 'ICMP TTL', 'os': 'Linux/Unix'}
    osint: Dict[str, Any] = field(default_factory=dict)  # {'dns': {}, 'whois': {}}
    services: Dict[int, Dict[str, Any]] = field(
        default_factory=dict
    )  # {21: {'protocol': 'tcp', 'service_data': {...}}}
    banners: Dict[int, str] = field(default_factory=dict)  # {80: 'nginx/1.24.0'}

    def add_service(self, port: int, protocol: str, service_data: Dict[str, Any]):
        """Добавляет сервис в результаты"""
        self.services[port] = {"protocol": protocol, "service_data": service_data}

    def add_banner(self, port: int, banner: str):
        """Добавляет баннер"""
        self.banners[port] = banner

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь (как в твоем примере)"""
        return {
            "host": self.host,
            "open_ports": self.open_ports,
            "os_info": self.os_info,
            "osint": self.osint,
            "services": self.services,
            "banners": self.banners,
        }
