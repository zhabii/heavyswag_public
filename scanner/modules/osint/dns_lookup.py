from typing import Dict, Any, List
import dns.resolver
import ipaddress
import sys
import os

# Добавляем путь для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))

from utils.verbose_mixin import VerboseMixin  # Новый импорт


class DNSLookup(VerboseMixin):  # Добавляем наследование
    def __init__(self, is_verbose: bool = True):
        self.is_verbose = is_verbose

    def is_ip_address(self, address_string):
        try:
            ipaddress.ip_address(address_string)
            return True
        except ValueError:
            return False

    def lookup(self, address_string) -> Dict[str, Any]:
        self.verbose_print(
            f"[*] DNS lookup для {address_string}..."
        )  # Используем миксин

        result = {"target": address_string}

        if self.is_ip_address(address_string):
            result.update(self._reverse_lookup(address_string))
        else:
            result.update(self._hostname_lookup(address_string))

        return result

    def _hostname_lookup(self, hostname: str) -> Dict[str, Any]:
        result = {}

        # A record (IPv4)
        try:
            a_records = dns.resolver.resolve(hostname, "A")
            result["A"] = [val.to_text() for val in a_records]
        except:
            pass

        # AAAA record (IPv6)
        try:
            aaaa_records = dns.resolver.resolve(hostname, "AAAA")
            result["AAAA"] = [val.to_text() for val in aaaa_records]
        except:
            pass

        # NS records
        try:
            ns_records = dns.resolver.resolve(hostname, "NS")
            result["NS"] = [val.to_text() for val in ns_records]
        except:
            pass

        # MX records
        try:
            mx_records = dns.resolver.resolve(hostname, "MX")
            result["MX"] = [f"{val.preference} {val.exchange}" for val in mx_records]
        except:
            pass

        # TXT records
        try:
            txt_records = dns.resolver.resolve(hostname, "TXT")
            result["TXT"] = [val.to_text() for val in txt_records]
        except:
            pass

        # CNAME record
        try:
            cname_records = dns.resolver.resolve(hostname, "CNAME")
            result["CNAME"] = [val.to_text() for val in cname_records]
        except:
            pass

        return result

    def _reverse_lookup(self, ip_address: str) -> Dict[str, Any]:
        result = {}

        try:
            reverse_name = dns.reversename.from_address(ip_address)
            ptr_records = dns.resolver.resolve(reverse_name, "PTR")
            result["PTR"] = [val.to_text() for val in ptr_records]
        except Exception as e:
            self.verbose_print(
                f"[-] Ошибка reverse DNS lookup: {e}"
            )  # Используем миксин

        return result


if __name__ == "__main__":
    print()
    
    
    dnslookup = DNSLookup()
    result = dnslookup.lookup("example.com")
    print(result)
