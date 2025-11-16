from typing import List
import socket
import sys
import os

# Добавляем путь для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.verbose_mixin import VerboseMixin  # Новый импорт


class BannerGrubber(VerboseMixin):  # Добавляем наследование
    def __init__(
        self,
        host: str,
        tcp_ports: List[int] = None,
        udp_ports: List[int] = None,
        verbose: bool = True,
    ):
        self.host = host
        self.tcp_ports = tcp_ports or []
        self.udp_ports = udp_ports or []
        self.is_verbose = verbose  # Переименовываем для VerboseMixin

        self.result_banners = {}  # формат {port: {"tr_proto: "...", "banner": "..."}}

    # УДАЛЯЕМ старый verbose_print - используем миксин
    # def verbose_print(self, s: str):
    #     if self.verbose:
    #         print(s)

    def start(self, payloads: List[str] = None):
        if not self.tcp_ports and not self.udp_ports:
            self.verbose_print(f"[*] Нет портов для сканирования для {self.host}")
            return

        for port in self.tcp_ports:
            if self.grab_tcp(port, payloads):
                continue

        for port in self.udp_ports:
            if self.grab_udp(port, payloads):
                continue

        return self.result_banners

    def grab_tcp(self, port: int, payloads: List[str] = None):
        # пробуем подключиться и послушать сервер
        banner = self._tcp_server_first(port)
        if banner:
            self._save(port, banner, "TCP-SF")
            return True

        # если не получили данные - сами отправляем их
        banner = self._tcp_client_first(port, payloads=payloads)
        if banner:
            self._save(port, banner, "TCP-CF")
            return True

    # UDP в 99.9% случаях принимает сообщение от клиента.
    def grab_udp(self, port: int, payloads: List[str] = None):
        banner = self._udp_client_first(port, payloads=payloads)
        if banner:
            self._save(port, banner, "UDP")
            return self.result_banners

    def _save(self, port: int, data: bytes, tr_proto: str):
        try:
            # Декодируем с обработкой ошибок
            banner = data.decode(errors="ignore")
            
            # Объединяем многострочные баннеры в одну строку
            banner = banner.replace('\r\n', ' ')  # заменяем CRLF на пробел
            banner = banner.replace('\n', ' ')    # заменяем LF на пробел  
            banner = banner.replace('\r', ' ')    # заменяем CR на пробел
            
            # Убираем лишние пробелы и спецсимволы
            banner = " ".join(banner.split())
            
            # Обрезаем слишком длинные баннеры (опционально)
            if len(banner) > 500:
                banner = banner[:500] + "..."
            
            self.result_banners[port] = {
                "tr_proto": tr_proto,
                "banner": banner,
            }
            
            # Показываем баннер если verbose
            self.verbose_print(f"[+] {self.host}:{port}/{tr_proto} -> {banner}")
            
        except Exception as e:
            self.verbose_print(f"[!] Ошибка обработки баннера для порта {port}: {e}")
        
    def _tcp_server_first(self, port: int, timeout: float = 3.0):
        sock = None  # чтобы не вызвать исключение при закрытии
        try:
            sock = socket.create_connection((self.host, port), timeout=timeout)
            sock.settimeout(timeout)  # задает timeout на recv

            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except socket.timeout:
                    break

            data = b"".join(chunks)
            return data if data else None

        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

    def _tcp_client_first(self, port: int, timeout: float = 3.0, payloads=None):
        # Пэйлоады по умолчанию
        if not payloads:
            payloads = [
                "OPTIONS / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
            ]

        for payload in payloads:
            self.verbose_print(f'[*] TCP/{port} пробуем пэйлоад: {repr(payload)}')
            sock = None
            try:
                sock = socket.create_connection((self.host, port), timeout=timeout)
                sock.settimeout(timeout)
                sock.sendall(payload.encode())

                chunks = []
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    except socket.timeout:
                        break

                data = b"".join(chunks)
                if data:
                    return data  # если получили ответ сразу выходим

            except Exception:
                pass

            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass

        return None

    def _udp_client_first(self, port: int, timeout: float = 3.0, payloads=None):
        if not payloads:
            payloads = ["\x00"]

        for payload in payloads:
            self.verbose_print(f'[*] UDP/{port} пробуем пэйлоад: {repr(payload)}')
        
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(payload.encode(), (self.host, port))
                data, _ = sock.recvfrom(4096)
                if data:
                    return data

            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass


if __name__ == "__main__":
    from pprint import pprint 
    TARGET = "10.226.133.193"
    grubber = BannerGrubber(TARGET, tcp_ports=[21, 80])
    result = grubber.start()
    pprint(result)