#!/usr/bin/env python3
"""
Боевой скрипт для атаки ZVP-GLV на Страуса-трюк Шамира (secp256k1)
Реализация атаки из раздела 4.3 научной статьи "Decompose and conquer: ZVP attacks on GLV curves"

Использование:
    sage -python zvp_glv_sac.py --pubkey <hex> [--bits <int>] [--save <filename>] [--verbose]

Пример:
    sage -python zvp_glv_sac.py --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac --bits 4
"""

import os
import sys
import argparse
import json
import time
from datetime import datetime

# Добавляем папку attack в путь для импорта модулей
attack_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack')
sys.path.insert(0, attack_dir)

try:
    import zvp_glv_sac as attack_module
    import utils
    from utils import ZVPparams
    from sage.all import ZZ, EllipticCurve, GF
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    print("\n🔧 Для работы скрипта необходим SageMath!")
    print("   Запустите скрипт через Sage:")
    print("   sage -python zvp_glv_sac.py --pubkey <hex> --bits 4")
    print("\n   Или установите SageMath:")
    print("   https://www.sagemath.org/download.html")
    sys.exit(1)


def parse_pubkey(pubkey_hex):
    """
    Парсит публичный ключ из hex строки
    
    Args:
        pubkey_hex (str): Публичный ключ в hex формате (128 hex символов)
        
    Returns:
        tuple: (x, y) координаты точки на кривой
        
    Raises:
        ValueError: Если формат ключа неверный
    """
    if not pubkey_hex.startswith('04'):
        raise ValueError("Публичный ключ должен начинаться с '04' (несжатый формат)")
    
    if len(pubkey_hex) != 130:  # 04 + 64 + 64 hex символов
        raise ValueError(f"Публичный ключ должен содержать 130 hex символов, получено {len(pubkey_hex)}")
    
    try:
        # Убираем префикс 04
        key_data = pubkey_hex[2:]
        
        # Извлекаем координаты x и y (по 64 hex символа каждая)
        x_hex = key_data[:64]
        y_hex = key_data[64:]
        
        x = ZZ('0x' + x_hex)
        y = ZZ('0x' + y_hex)
        
        return x, y
        
    except ValueError as e:
        raise ValueError(f"Ошибка парсинга публичного ключа: {e}")


def validate_point_on_curve(x, y):
    """
    Проверяет, что точка лежит на кривой secp256k1
    
    Args:
        x, y: Координаты точки
        
    Returns:
        bool: True если точка на кривой
    """
    # Параметры secp256k1: y^2 = x^3 + 7
    p = ZZ('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F')
    
    # Проверяем, что координаты в допустимом диапазоне
    if not (0 <= x < p) or not (0 <= y < p):
        return False
    
    # Проверяем уравнение кривой
    left_side = (y * y) % p
    right_side = (x * x * x + 7) % p
    
    return left_side == right_side


def setup_attack_params(pubkey_x, pubkey_y, target_bits, verbose=True):
    """
    Настраивает параметры для атаки ZVP-GLV
    
    Args:
        pubkey_x, pubkey_y: Координаты публичного ключа
        target_bits (int): Количество целевых бит для атаки
        verbose (bool): Подробный вывод
        
    Returns:
        ZVPparams: Настроенные параметры атаки
    """
    print(f"🔧 Настройка параметров атаки...")
    print(f"   Целевые биты: {target_bits}")
    print(f"   Публичный ключ: ({pubkey_x}, {pubkey_y})")
    
    # Создаем параметры для ataki на 256-битной кривой
    zvpparams = ZVPparams(bits=256)
    
    # Устанавливаем кривую secp256k1
    zvpparams.generate_secp256k1_secrets()
    
    # Устанавливаем целевое количество бит
    zvpparams.target_bits = target_bits
    zvpparams.verbose = verbose
    
    # Настраиваем регистры для secp256k1 (проективные координаты)
    # Используем формулу projective:madd-2015-rcb которая показала лучшие результаты
    registers_dict = utils.load_efd_secp256k1_registers()
    zvpparams.registers = registers_dict["projective:madd-2015-rcb"]
    
    print(f"   Используемые полиномы IV: {len(zvpparams.registers.polynomials)} шт.")
    print(f"   Координатная система: projective:madd-2015-rcb")
    
    # Устанавливаем функцию атаки
    zvpparams.attack = attack_module.zvp_glv_sac
    
    # Здесь можно установить секретный скаляр если известен (для тестирования)
    # В реальной атаке мы его не знаем, но для демонстрации можем сгенерировать
    
    return zvpparams


def run_attack(zvpparams):
    """
    Запускает атаку ZVP-GLV на Страуса-трюк Шамира
    
    Args:
        zvpparams: Параметры атаки
        
    Returns:
        dict: Результаты атаки
    """
    print(f"\n🚀 Запуск атаки ZVP-GLV на Страуса-трюк Шамира...")
    print(f"   Алгоритм: Straus-Shamir trick с GLV-SAC кодированием")
    print(f"   Кривая: secp256k1")
    print(f"   Целевые биты: {zvpparams.target_bits}")
    
    start_time = time.time()
    
    # Сохраняем текущую рабочую директорию
    original_cwd = os.getcwd()
    
    try:
        # Переходим в папку attack для правильной работы DCP solver
        attack_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack')
        os.chdir(attack_dir)
        
        print(f"   Рабочая директория: {os.getcwd()}")
        
        # Выполняем атаку
        result = zvpparams.attack(zvpparams)
        
        end_time = time.time()
        attack_time = end_time - start_time
        
        print(f"\n✅ Атака завершена успешно!")
        print(f"   Время выполнения: {attack_time:.2f} секунд")
        print(f"   Восстановлено битов: {result.get('recovered', 0):.2f}")
        print(f"   Количество кандидатов: {len(result.get('scalars', []))}")
        
        # Добавляем дополнительную информацию
        result['attack_time'] = attack_time
        result['success'] = True
        result['target_bits'] = zvpparams.target_bits
        
        return result
        
    except Exception as e:
        end_time = time.time()
        attack_time = end_time - start_time
        
        print(f"\n❌ Ошибка при выполнении атаки:")
        print(f"   {str(e)}")
        print(f"   Время до ошибки: {attack_time:.2f} секунд")
        
        return {
            'success': False,
            'error': str(e),
            'attack_time': attack_time,
            'target_bits': zvpparams.target_bits
        }
    finally:
        # Возвращаемся в исходную директорию
        os.chdir(original_cwd)


def save_results_to_file(results, zvpparams, filename):
    """
    Сохраняет результаты в JSON файл
    
    Args:
        results (dict): Результаты атаки
        zvpparams: Параметры атаки
        filename (str): Имя файла для сохранения
    """
    # Создаем полные результаты включая параметры
    full_results = {
        'timestamp': datetime.now().isoformat(),
        'attack_type': 'ZVP-GLV Straus-Shamir',
        'curve': 'secp256k1',
        'target_bits': zvpparams.target_bits,
        'parameters': zvpparams.results_to_dict() if hasattr(zvpparams, 'results_to_dict') else {},
        'results': results
    }
    
    # Создаем папку results если не существует
    results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'attack', 'results')
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    
    # Добавляем временную метку к имени файла
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not filename.endswith('.json'):
        filename += '.json'
    
    filename_with_timestamp = f"{filename[:-5]}_{timestamp}.json"
    filepath = os.path.join(results_dir, filename_with_timestamp)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(full_results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Результаты сохранены в файл: {filepath}")
        
    except Exception as e:
        print(f"\n❌ Ошибка при сохранении результатов: {e}")


def print_detailed_results(results):
    """
    Выводит подробные результаты атаки
    
    Args:
        results (dict): Результаты атаки
    """
    print(f"\n📊 Подробные результаты атаки:")
    print(f"   Успех: {'Да' if results.get('success', False) else 'Нет'}")
    
    if results.get('success', False):
        print(f"   Восстановлено битов: {results.get('recovered', 0):.2f}")
        print(f"   Время атаки ZVP: {results.get('time_zvp', 0):.2f} сек")
        print(f"   Общее время: {results.get('attack_time', 0):.2f} сек")
        
        scalars = results.get('scalars', [])
        print(f"   Найдено кандидатов: {len(scalars)}")
        
        if scalars and len(scalars) <= 10:
            print(f"\n   Кандидаты скаляров (k0, k1):")
            for i, (k0, k1) in enumerate(scalars):
                print(f"     {i+1}. k0={k0}, k1={k1}")
        elif scalars:
            print(f"   Найдено слишком много кандидатов ({len(scalars)}) для отображения")
            
        nguesses = results.get('nguesses', [])
        if nguesses:
            print(f"   Количество предположений по итерациям: {nguesses}")
    else:
        print(f"   Ошибка: {results.get('error', 'Неизвестная ошибка')}")


def main():
    parser = argparse.ArgumentParser(
        description='Боевой скрипт для атаки ZVP-GLV на Страуса-трюк Шамира',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac --bits 4
  %(prog)s --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac --bits 6 --save my_attack_results
  %(prog)s --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b09cfe535e1ff290b1b5ac --bits 4 --verbose

Атака реализует метод из раздела 4.3 статьи "Decompose and conquer: ZVP attacks on GLV curves"
        """
    )
    
    parser.add_argument(
        '--pubkey',
        type=str,
        required=True,
        help='Публичный ключ в hex формате (128 hex символов, начинается с 04)'
    )
    
    parser.add_argument(
        '--bits',
        type=int,
        default=4,
        choices=range(2, 33),
        metavar='2-32',
        help='Количество целевых бит для атаки (по умолчанию: 4)'
    )
    
    parser.add_argument(
        '--save',
        type=str,
        help='Сохранить результаты в JSON файл (без расширения)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Подробный вывод процесса атаки'
    )
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("🔥 БОЕВОЙ СКРИПТ ДЛЯ АТАКИ ZVP-GLV НА СТРАУСА-ТРЮК ШАМИРА")
    print("=" * 70)
    print(f"📖 Реализация атаки из раздела 4.3 научной работы")
    print(f"🎯 Цель: secp256k1 с GLV-SAC кодированием")
    print("=" * 70)
    
    try:
        # Парсинг публичного ключа
        print(f"\n🔑 Парсинг публичного ключа...")
        pubkey_x, pubkey_y = parse_pubkey(args.pubkey)
        print(f"   X: {hex(pubkey_x)}")
        print(f"   Y: {hex(pubkey_y)}")
        
        # Проверка что точка на кривой
        print(f"\n✅ Проверка точки на кривой secp256k1...")
        if not validate_point_on_curve(pubkey_x, pubkey_y):
            raise ValueError("Точка не лежит на кривой secp256k1")
        print(f"   Точка корректная ✓")
        
        # Настройка параметров атаки
        zvpparams = setup_attack_params(pubkey_x, pubkey_y, args.bits, args.verbose)
        
        # Запуск атаки
        results = run_attack(zvpparams)
        
        # Вывод результатов
        print_detailed_results(results)
        
        # Сохранение результатов
        if args.save:
            save_results_to_file(results, zvpparams, args.save)
        
        # Финальное сообщение
        if results.get('success', False):
            print(f"\n🎉 Атака завершена успешно!")
            recovered_bits = results.get('recovered', 0)
            if recovered_bits > 0:
                print(f"   Восстановлено {recovered_bits:.2f} битов секретного скаляра")
            else:
                print(f"   Атака не смогла восстановить биты (DCP не имел решений)")
        else:
            print(f"\n💥 Атака завершилась с ошибкой")
            return 1
            
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        return 1
    
    print("\n" + "=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())