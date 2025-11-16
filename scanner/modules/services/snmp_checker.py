import socket
import subprocess
from typing import List, Dict, Any

from scanner.modules.services.base_checker import BaseServiceChecker  # Абсолютный импорт!


class SNMPChecker(BaseServiceChecker):
    DEFAULT_PORTS = [161]
    
    def get_service_payloads(self):
        """SNMP community strings для проверки"""
        return [
            "public", "private", "secret", "community",
            "read"
        ]
    
    def _check_service_specific(self, ports: List[int]) -> Dict[str, Any]:
        service_info = {
            'available_communities': [],
            'system_info': {},
            'network_interfaces': [],
            'processes': [],
            'errors': []
        }
        
        for port in ports:
            try:
                port_info = self._check_snmp_port(port)
                if port_info:
                    service_info['available_communities'].extend(port_info.get('available_communities', []))
                    if port_info.get('system_info'):
                        service_info['system_info'] = port_info['system_info']
                    if port_info.get('network_interfaces'):
                        service_info['network_interfaces'] = port_info['network_interfaces']
                    if port_info.get('processes'):
                        service_info['processes'] = port_info['processes']
            except Exception as e:
                service_info['errors'].append(f"Port {port}: {str(e)}")
        
        return service_info
            
    def _check_snmp_port(self, port: int) -> Dict[str, Any]:
        """Проверка SNMP на конкретном порту"""
        result = {
            'available_communities': [],
            'system_info': {},
            'network_interfaces': [],
            'processes': []
        }
        
        # Проверяем все community strings
        for community in self.get_service_payloads():
            community_info = self._check_snmp_community(port, community)
            if community_info.get('available'):
                result['available_communities'].append(community)
                # Собираем информацию с первого доступного community
                if not result['system_info'] and community_info.get('system_info'):
                    result['system_info'] = community_info['system_info']
                if not result['network_interfaces'] and community_info.get('interfaces'):
                    result['network_interfaces'] = community_info['interfaces']
                if not result['processes'] and community_info.get('processes'):
                    result['processes'] = community_info['processes']
        
        return result if result['available_communities'] else None
            
    def _check_snmp_community(self, port: int, community: str) -> Dict[str, Any]:
        """Проверка доступности community string"""
        try:
            # Сначала пробуем через системные утилиты (более надежно)
            if self._check_with_snmpget(port, community):
                self.verbose_print(f'[+] SNMP {port}: community "{community}" доступен')
                info = self._gather_snmp_info(port, community)
                return {'available': True, **info}
            else:
                self.verbose_print(f'[-] SNMP {port}: community "{community}" недоступен')
                return {'available': False}
                
        except Exception as e:
            self.verbose_print(f'[!] SNMP {port}: ошибка проверки "{community}" - {e}')
            return {'available': False}
    
    def _check_with_snmpget(self, port: int, community: str) -> bool:
        """Проверка community через snmpget (если установлен)"""
        try:
            # Пробуем получить системное описание
            cmd = [
                'snmpget', '-v', '2c', '-c', community,
                f'{self.target_ip}:{port}', '1.3.6.1.2.1.1.1.0',
                '-t', '2'  # timeout 2 секунды
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=3
            )
            
            return result.returncode == 0 and 'STRING:' in result.stdout
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            # Если snmpget не установлен или таймаут, пробуем raw socket
            return self._check_with_raw_socket(port, community)
    
    def _check_with_raw_socket(self, port: int, community: str) -> bool:
        """Проверка через raw socket (fallback метод)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Базовый SNMP GET запрос
            packet = self._create_snmp_get_packet(community, '1.3.6.1.2.1.1.1.0')
            
            sock.sendto(packet, (self.target_ip, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            
            return len(data) > 0
            
        except socket.timeout:
            return False
        except Exception:
            return False
    
    def _create_snmp_get_packet(self, community: str, oid: str) -> bytes:
        """Создает SNMP GET пакет"""
        # Это упрощенная версия - в реальности нужен полный SNMP парсинг
        community_bytes = community.encode('ascii')
        
        # Базовый SNMP GET запрос (упрощенно)
        packet = bytearray()
        packet.extend(bytes.fromhex('30290201010406'))  # SNMP header
        packet.append(len(community_bytes))
        packet.extend(community_bytes)
        packet.extend(bytes.fromhex('a01c0204567890c0020100020100300e300c06082b060102010101000500'))
        
        return bytes(packet)
    
    def _gather_snmp_info(self, port: int, community: str) -> Dict[str, Any]:
        """Сбор информации через SNMP"""
        info = {
            'system_info': {},
            'interfaces': [],
            'processes': []
        }
        
        # Системная информация
        system_oids = {
            'description': '1.3.6.1.2.1.1.1.0',
            'name': '1.3.6.1.2.1.1.5.0',
            'location': '1.3.6.1.2.1.1.6.0',
            'contact': '1.3.6.1.2.1.1.4.0',
            'uptime': '1.3.6.1.2.1.1.3.0'
        }
        
        for key, oid in system_oids.items():
            value = self._snmp_get(port, community, oid)
            if value:
                info['system_info'][key] = value
        
        # Сетевые интерфейсы
        try:
            cmd = [
                'snmpwalk', '-v', '2c', '-c', community,
                f'{self.target_ip}:{port}', '1.3.6.1.2.1.2.2.1.2',
                '-t', '2'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                interfaces = []
                for line in result.stdout.split('\n')[:10]:
                    if 'STRING:' in line:
                        iface = line.split('STRING:')[1].strip().strip('"')
                        interfaces.append(iface)
                info['interfaces'] = interfaces
        except:
            pass
        
        # Процессы
        try:
            cmd = [
                'snmpwalk', '-v', '2c', '-c', community,
                f'{self.target_ip}:{port}', '1.3.6.1.2.1.25.4.2.1.2',
                '-t', '2'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                processes = []
                for line in result.stdout.split('\n')[:15]:
                    if 'STRING:' in line:
                        process = line.split('STRING:')[1].strip().strip('"')
                        processes.append(process)
                info['processes'] = processes
        except:
            pass
        
        return info
    
    def _snmp_get(self, port: int, community: str, oid: str) -> str:
        """Выполняет SNMP GET запрос"""
        try:
            cmd = [
                'snmpget', '-v', '2c', '-c', community,
                f'{self.target_ip}:{port}', oid,
                '-t', '2'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0 and 'STRING:' in result.stdout:
                return result.stdout.split('STRING:')[1].strip().strip('"')
        except:
            pass
        return None


if __name__ == "__main__":
    TARGET = '127.0.0.1'
    PORTS = [161]
    
    checker = SNMPChecker(TARGET, is_verbose=True)
    print(checker.run(PORTS))