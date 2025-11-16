import whois
import sys
import os

# Добавляем путь для импортов
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from utils.verbose_mixin import VerboseMixin  # Новый импорт


class WhoisLookup(VerboseMixin):  # Добавляем наследование
    def __init__(self, is_verbose: bool = True):  # Переименовываем для consistency
        self.is_verbose = is_verbose
    
    def lookup(self, target: str):
        self.verbose_print(f"[*] WHOIS поиск по {target}...")  # Используем миксин
        
        try:
            # Просто получаем whois и возвращаем основные поля
            w = whois.whois(target)
            
            result = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
            
            self.verbose_print("[+] WHOIS lookup завершен")
            return result
            
        except Exception as e:
            self.verbose_print(f"[!] WHOIS ошибка: {e}")  # Используем миксин
            return {}
        
        
if __name__ == '__main__':
    wl = WhoisLookup()
    result = wl.lookup('example.com')  # {'domain_name': 'EXAMPLE.COM', 'registrar': 'RESERVED-Internet Assigned Numbers Authority', 'creation_date': datetime.datetime(1995, 8, 14, 4, 0, tzinfo=tzoffset('UTC', 0)), 'expiration_date': datetime.datetime(2026, 8, 13, 4, 0, tzinfo=tzoffset('UTC', 0)), 'name_servers': ['A.IANA-SERVERS.NET', 'B.IANA-SERVERS.NET']}
    print(result) 