#!/usr/bin/env python3
import argparse
import sys
import os

# Добавляем путь для импортов
sys.path.append(os.path.dirname(__file__))

from scanner.orchestrator import Orchestrator
from scanner.output.json_output import save_results


def main():
    
    parser = argparse.ArgumentParser(
        description='Network Security Scanner v2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
Примеры использования:
  %(prog)s 10.226.133.193                    # Базовое сканирование
  %(prog)s example.com -v                    # Подробный вывод
  %(prog)s 192.168.1.1 -o scan_results.json  # Сохранить в JSON
  %(prog)s 127.0.0.1 --ports 80,443,22      # Сканировать特定ные порты
        '''
    )
    
    parser.add_argument(
        'target', 
        help='Целевой хост или IP адрес'
    )
    
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true',
        help='Подробный вывод'
    )
    
    parser.add_argument(
        '-o', '--output', 
        help='Сохранить результаты в JSON файл'
    )
    
    parser.add_argument(
        '--ports',
        help='Сканировать特定ные порты (например: 80,443,22 или 1-1000)',
        default=None
    )
    
    parser.add_argument(
        '--no-web-scan',
        action='store_true',
        help='Не предлагать веб-сканирование'
    )
    
    args = parser.parse_args()
    
    try:
        print(f"Сканирование {args.target}...")
        
        # Запускаем сканирование
        scanner = Orchestrator(args.target, is_verbose=args.verbose)
        results = scanner.scan_host()
        
        # Сохраняем если нужно
        if args.output:
            save_results(results, args.output)
            print(f"💾 Результаты сохранены в {args.output}")
        
        # Показываем сводку
        scanner.print_summary()
        
        print("Сканирование завершено!")
        
    except KeyboardInterrupt:
        print("\n⏹Сканирование прервано пользователем")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()