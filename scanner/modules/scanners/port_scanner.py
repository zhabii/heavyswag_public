from scapy.all import *
from enum import Enum
from queue import Queue
from typing import List
import time
import threading

from scanner.utils.verbose_mixin import VerboseMixin

class ScanMode(Enum):
    SYN = "SYN"
    TCP = "TCP"  
    UDP = "UDP"
    
    @classmethod
    def from_string(cls, mode_str: str):
        """Конвертирует строку в ScanMode"""
        mode_str = mode_str.upper().strip()
        for mode in cls:
            if mode.value == mode_str:
                return mode
        raise ValueError(f"Unknown scan mode: {mode_str}")


class PortScanner(VerboseMixin):
    def __init__(
        self,
        target_ip: str,
        target_ports: List[int] = None,
        mode: ScanMode = ScanMode.SYN,
        is_verbose: bool = True,
        threads: int = 10,
        timeout: int = 2
    ):
        self.target_ip = target_ip
        self.target_ports = target_ports or list(range(1, 1001))
        self.mode = mode if isinstance(mode, ScanMode) else ScanMode.from_string(mode)
        self.is_verbose = is_verbose
        self.threads = threads
        self.timeout = timeout

        self.lock = threading.Lock()
        self.port_queue = Queue()
        self.open_ports = []

    def worker(self):
        """Воркер для скана одного порта"""
        while not self.port_queue.empty():
            try:
                port = self.port_queue.get()
                if port is None:
                    break

                if self.mode == ScanMode.SYN:
                    self.syn_scan(self.target_ip, port)
                elif self.mode == ScanMode.UDP:
                    self.udp_scan(self.target_ip, port)
                elif self.mode == ScanMode.TCP:
                    self.tcp_scan(self.target_ip, port)

                self.port_queue.task_done()
            except Exception as e:
                self.verbose_print(f"[!] Worker error: {e}")
                break

    def scan(self):
        """Запускает сканирование, возвращает List[int] открытых портов"""
        self.verbose_print(f"[*] Начало {self.mode} сканирования для {self.target_ip}")
        self.verbose_print(
            f"[*] Сканирование {len(self.target_ports)} портов с {self.threads} потоками..."
        )

        start_time = time.time()

        for port in self.target_ports:
            self.port_queue.put(port)

        thread_pull = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread_pull.append(thread)
            thread.start()

        for thread in thread_pull:
            thread.join()

        elapsed_time = time.time() - start_time
        self.verbose_print(f"[*] Сканирование завершено за {elapsed_time:.2f} секунд")
        self.verbose_print(f"[*] Найдено {len(self.open_ports)} открытых портов")

        return self.open_ports

    def tcp_scan(self, target_ip, target_port):
        """TCP connect scan (можно реализовать позже)"""
        self.verbose_print(f"[!] TCP connect scan для {target_ip}:{target_port} не реализован")
        pass

    def syn_scan(self, ip, port):
        try:
            syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
            responce = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if not responce:
                self.verbose_print(f"[*] {ip}:{port} TCP filtered (reason: no answer)")
            elif responce.haslayer(TCP):
                tcp_layer = responce.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    with self.lock:
                        self.open_ports.append(port)
                    print(f"[*] {ip}:{port} TCP open (reason: SYN-ACK)")

                    # закрываем соединение
                    rst_packet = IP(dst=ip) / TCP(dport=port, flags="R")
                    send(rst_packet, verbose=0)

                elif tcp_layer.flags == 0x14:  # RST
                    self.verbose_print(f"[*] {ip}:{port} TCP close (reason: RST)")
            else:
                self.verbose_print(f"[*] {ip}:{port} undefined")
            return responce
        except Exception as e:
            self.verbose_print(f"[!] Error scanning {ip}:{port}: {e}")

    def udp_scan(self, ip, port):
        try:
            upd_packet = IP(dst=ip) / UDP(dport=port)
            responce = sr1(upd_packet, timeout=self.timeout, verbose=0)

            if not responce:
                with self.lock:
                    self.open_ports.append(port)
                print(f"[*] {ip}:{port} UDP open/filtered (reason: no answer)")
                return
            elif responce.haslayer(ICMP):
                self.verbose_print(f"[*] {ip}:{port} UDP close (reason: ICMP)")
            elif responce.haslayer(UDP):
                with self.lock:
                    self.open_ports.append(port)
                print(f"[*] {ip}:{port} UDP open/filtered (reason: UDP responce)")
                return
        except Exception as e:
            self.verbose_print(f"[!] Error scanning {ip}:{port}: {e}")


if __name__ == "__main__":
    # примеры SYN и UDP
    s = PortScanner("10.226.133.193", (80, 8080, 8000))
    #s = PortScanner("10.226.133.193", (80, 8080, 8000), mode=ScanMode.UDP)
    result = s.scan()  # [80]