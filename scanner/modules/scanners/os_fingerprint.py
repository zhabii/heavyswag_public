from scapy.all import *


class OSFingerprint:
    def __init__(self, timeout=2):
        self.timeout = timeout

    def detect(self, host: str) -> dict:
        # TTL от ICMP Echo Reply
        reply = sr1(IP(dst=host) / ICMP(), timeout=self.timeout, verbose=0)

        if not reply:
            return {"os": "Unknown", "ttl": None, "error": "No response"}

        ttl = reply.ttl
        os_guess = self._guess_os_by_ttl(ttl)

        return {"os": os_guess, "ttl": ttl, "method": "ICMP TTL"}

    def _guess_os_by_ttl(self, ttl):
        """Простое определение ОС по TTL"""
        if 60 <= ttl <= 64:
            return "Linux/Unix"
        elif 120 <= ttl <= 128:
            return "Windows"
        elif ttl == 255:
            return "Network Device"
        else:
            return f"Unknown (TTL: {ttl})"
        

if __name__ == '__main__':
    osfingerprinter = OSFingerprint()
    result = osfingerprinter.detect('10.226.133.193') # {'os': 'Linux/Unix', 'ttl': 64, 'method': 'ICMP TTL'}
    print(result)