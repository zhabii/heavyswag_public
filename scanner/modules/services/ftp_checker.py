import ftplib
from typing import List, Dict, Any

from scanner.modules.services.base_checker import BaseServiceChecker


class FTPChecker(BaseServiceChecker):
    DEFAULT_PORTS = [20, 21, 990]
    
    def get_service_payloads(self):
        """FTP пэйлоады для сбора баннера"""
        return [
            "\r\n",
            "NOOP\r\n",
            "HELP\r\n", 
            "SYST\r\n",
            "FEAT\r\n",
            "STAT\r\n",
            "AUTH TLS\r\n",
            "USER anonymous\r\n",
            "USER root\r\n",
        ]
    
    def _check_service_specific(self, ports: List[int]) -> Dict[str, Any]:
        service_info = {
            'anonymous_access': False,
            'files': []
        }
        
        try:
            for port in ports:
                if self._check_anonymous_login(port):
                    service_info['anonymous_access'] = True
                    
                    # Если получился вход, пробуем собрать файлы
                    files = self._check_files(port) 
                    service_info['files'].extend(files)
                    
        except Exception as e:
            self.verbose_print(f'[!] Ошибка проверки FTP: {e}')
        
        return service_info
            
    def _check_anonymous_login(self, port: int) -> bool:
        '''Проверка анонимного доступа'''
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target_ip, port, timeout=5)
            ftp.login()  # без параметров входит анонимно
            ftp.quit()
            self.verbose_print(f'[+] FTP {port}: анонимный доступ разрешен')
            return True
        except Exception as e: 
            self.verbose_print(f'[-] FTP {port}: анонимный доступ запрещен - {e}')
            return False
            
    def _check_files(self, port: int) -> List[str]:
        '''Листинг файлов на сервере'''
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target_ip, port, timeout=5)
            ftp.login()  # без параметров входит анонимно
            
            files = ftp.nlst()
            ftp.quit()
            
            if files:
                self.verbose_print(f'[+] Найдены файлы FTP {port}: {len(files)} файлов')
                return files[:10]  # чтобы не забивать вывод
            return []
            
        except Exception as e:
            self.verbose_print(f'[-] Ошибка листинга файлов FTP {port}: {e}')
            return []


if __name__ == "__main__":
    TARGET = '10.226.133.193'
    PORTS = [21]
    
    checker = FTPChecker(TARGET)
    print(checker.run(PORTS))