import re
import os
import mimetypes
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

from scanner.utils.verbose_mixin import VerboseMixin


class WhiteboxAnalyzer(VerboseMixin):
    """Анализирует код на небезопасные паттерны и секреты"""

    def __init__(self, is_verbose: bool = True):
        self.is_verbose = is_verbose

        # regex-ы секретов
        self.secret_patterns = {
            "api_key": [
                r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,50})["\']?',
            ],
            "passwords": [
                r'password["\']?\s*[:=]\s*["\']?([^"\'\s]{6,50})["\']?',
                r'passwd["\']?\s*[:=]\s*["\']?([^"\'\s]{6,50})["\']?',
                r'pwd["\']?\s*[:=]\s*["\']?([^"\'\s]{6,50})["\']?',
            ],
            "tokens": [
                r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,100})["\']?',
                r'bearer["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,100})["\']?',
                r'jwt["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{20,500})["\']?',
            ],
            "database_urls": [
                r"mysql://[^:\s]+:([^@\s]+)@",
                r"postgresql://[^:\s]+:([^@\s]+)@",
                r"mongodb://[^:\s]+:([^@\s]+)@",
                r"redis://[^:\s]+:([^@\s]+)@",
            ],
            "private_keys": [
                r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                r"-----BEGIN PRIVATE KEY-----",
            ],
            "emails": [r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"],
        }

        # regex-ы небезопасных паттернов
        self.unsafe_patterns = {
            "sql_injection": [
                r"execute\(.*\+.*\)",
                r"executescript\(.*\+.*\)",
                r"query\(.*\+.*\)",
                r'f"SELECT.*{.*}.*"',
                r'f"INSERT.*{.*}.*"',
                r'f"DELETE.*{.*}.*"',
                r'f"UPDATE.*{.*}.*"',
            ],
            "command_injection": [
                r"os\.system\(.*\+.*\)",
                r"subprocess\.call\(.*\+.*\)",
                r"subprocess\.Popen\(.*\+.*\)",
                r"exec\(.*\+.*\)",
                r"eval\(.*\)",
            ],
            "hardcoded_secrets": [
                r'secret\s*=\s*["\'][^"\']{10,}["\']',
                r'password\s*=\s*["\'][^"\']{6,}["\']',
                r'token\s*=\s*["\'][^"\']{10,}["\']',
            ],
            "debug_mode": [
                r"DEBUG\s*=\s*True",
                r"debug\s*=\s*true",
            ],
            "file_uploads": [
                r"move_uploaded_file",  # PHP
                r"f\.save\(.*\)",  # Python
            ],
        }

        # чувствительные имена
        self.sensitive_filenames = [
            ".env",
            "config",
            "settings",
            "secrets",
            "credentials",
            "dockerfile",
            "makefile",
            ".gitignore",
            ".dockerignore",
        ]

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Анализирует файл на уязвимости"""
        results = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "secrets_found": {},
            "unsafe_patterns": {},
            "file_info": {},
            "sensitive_filename": False,
            "errors": [],
        }

        try:
            file_path = Path(file_path)
            if not file_path.exists():
                results["errors"].append("Файл не существует")
                return results

            results["sensitive_filename"] = self._check_sensitive_filename(
                file_path.name
            )

            results["file_info"] = {
                "size": file_path.stat().st_size,
                "extension": file_path.suffix.lower(),
                "mime_type": mimetypes.guess_type(file_path)[0] or "unknown",
                "modified_time": file_path.stat().st_mtime,
            }

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                self.verbose_print(f"[!] Ошибка чтения {file_path}: {e}")

            results["secrets_found"] = self._find_secrets(content)
            results["unsafe_patterns"] = self._find_unsafe_patterns(content)

            self.verbose_print(f"[+] Проанализирован файл {file_path}")

        except Exception as e:
            results["errors"].append(f"Ошибка анализа: {str(e)}")
            self.verbose_print(f"[!] Ошибка анализа {file_path}: {e}")

        return results

    def _check_sensitive_filename(self, filename: str) -> bool:
        """Проверяет, является ли имя файла чувствительным"""
        filename = filename.lower()
        for sens_name in self.sensitive_filenames:
            if sens_name in filename:
                return True
        return False

    def _find_secrets(self, content: str) -> Dict[str, List[str]]:
        """Ищет секреты в содержимом файла"""
        secrets = {}

        for secret_type, patterns in self.secret_patterns.items():
            found = []
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    secret_value = match.group(1) if match.lastindex else match.group(0)
                    found.append(
                        {
                            "value": self._mask_secret(secret_value),
                            "line": self._get_line_number(content, match.start()),
                            "context": self._get_context(content, match.start(), 50),
                        }
                    )

            if found:
                secrets[secret_type] = found

        return secrets

    def _find_unsafe_patterns(self, content: str) -> Dict[str, List[str]]:
        """Ищет небезопасные паттерны в коде"""
        issues = {}

        for issue_type, patterns in self.unsafe_patterns.items():
            found = []
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    found.append(
                        {
                            "pattern": match.group(0),
                            "line": self._get_line_number(content, match.start()),
                            "context": self._get_context(content, match.start(), 100),
                        }
                    )

            if found:
                issues[issue_type] = found

        return issues

    def _get_line_number(self, content: str, position: int) -> int:
        """Определяет номер строки по позиции в тексте"""
        return content[:position].count("\n") + 1

    def _get_context(self, content: str, position: int, context_size: int) -> str:
        """Возвращает контекст вокруг найденного паттерна"""
        start = max(0, position - context_size)
        end = min(len(content), position + context_size)
        return content[start:end].replace("\n", " ").strip()

    def _mask_secret(self, secret: str) -> str:
        """Маскирует секреты для безопасного вывода"""
        if len(secret) <= 8:
            return "***"
        return secret[:4] + "***" + secret[-4:]


def main():
    """Пример использования"""
    analyzer = WhiteboxAnalyzer(is_verbose=True)

    # Анализ одного файла
    file_results = analyzer.analyze_file("/path/to/your/file.py")
    print("Результаты анализа файла:")
    import pprint

    pprint.pprint(file_results)


if __name__ == "__main__":
    main()
