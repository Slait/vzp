#!/usr/bin/env python3
"""
ДЕМОНСТРАЦИОННАЯ версия боевого скрипта для атаки ZVP-GLV на Страуса-трюк Шамира

ВНИМАНИЕ: Это демонстрационная версия, которая симулирует работу атаки без требования
полной установки SageMath и PARI/GP. Для реальной атаки используйте zvp_glv_sac.py

Использование:
    python3 zvp_glv_sac_demo.py --pubkey <hex> [--bits <int>] [--save <filename>] [--verbose]

Пример:
    python3 zvp_glv_sac_demo.py --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac --bits 4
"""

import os
import sys
import argparse
import json
import time
import random
from datetime import datetime


def parse_pubkey(pubkey_hex):
    """Парсит публичный ключ из hex строки"""
    if not pubkey_hex.startswith('04'):
        raise ValueError("Публичный ключ должен начинаться с '04' (несжатый формат)")
    
    if len(pubkey_hex) != 130:
        raise ValueError(f"Публичный ключ должен содержать 130 hex символов, получено {len(pubkey_hex)}")
    
    try:
        key_data = pubkey_hex[2:]
        x_hex = key_data[:64]
        y_hex = key_data[64:]
        x = int('0x' + x_hex, 16)
        y = int('0x' + y_hex, 16)
        return x, y
    except ValueError as e:
        raise ValueError(f"Ошибка парсинга публичного ключа: {e}")


def validate_point_on_curve(x, y):
    """Проверяет, что точка лежит на кривой secp256k1"""
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    
    if not (0 <= x < p) or not (0 <= y < p):
        return False
    
    left_side = (y * y) % p
    right_side = (x * x * x + 7) % p
    
    return left_side == right_side


def simulate_dcp_solution(target_bits, verbose=False):
    """
    Симулирует решение DCP проблемы
    Возвращает кандидатов скаляров в GLV-SAC представлении
    """
    if verbose:
        print(f"🔍 Симуляция решения DCP для {target_bits} битов...")
    
    # Симулируем процесс итеративного восстановления битов
    candidates = []
    nguesses = [2]  # Начинаем с 2 начальных предположений
    
    # GLV-SAC представление: (g0, g1) ∈ {(1,0), (-1,0), (1,1), (-1,-1)}
    sac_values = [(1, 0), (-1, 0), (1, 1), (-1, -1)]
    
    # Начальные кандидаты
    current_candidates = [([1], [0]), ([1], [1])]
    
    for bit in range(target_bits - 1):
        if verbose:
            print(f"   Итерация {bit + 1}: обрабатываю {len(current_candidates)} кандидатов")
        
        new_candidates = []
        
        for k0_bits, k1_bits in current_candidates:
            # Для каждого кандидата пробуем все возможные следующие биты
            for g0, g1 in sac_values:
                # Симулируем решение DCP - предполагаем что ~70% имеют решение
                if random.random() < 0.7:
                    new_k0 = [g0] + k0_bits
                    new_k1 = [g1] + k1_bits
                    new_candidates.append((new_k0, new_k1))
        
        current_candidates = new_candidates
        nguesses.append(len(current_candidates))
        
        if verbose:
            print(f"   Количество предположений: {len(current_candidates)}")
    
    # Рассчитываем количество восстановленных битов
    if len(current_candidates) > 0:
        recovered_bits = 2 * target_bits - (len(current_candidates).bit_length() - 1 if len(current_candidates) > 1 else 0)
    else:
        recovered_bits = 0
    
    return {
        'scalars': current_candidates,
        'nguesses': nguesses,
        'recovered': max(0, recovered_bits)
    }


def run_demo_attack(pubkey_x, pubkey_y, target_bits, verbose=True):
    """Симулирует запуск атаки ZVP-GLV"""
    
    print(f"\n🚀 ДЕМОНСТРАЦИЯ атаки ZVP-GLV на Страуса-трюк Шамира...")
    print(f"   Алгоритм: Straus-Shamir trick с GLV-SAC кодированием")
    print(f"   Кривая: secp256k1")
    print(f"   Целевые биты: {target_bits}")
    print(f"   Координатная система: projective:madd-2015-rcb")
    print(f"   Промежуточные полиномы: 5 шт. (f1, f8, f9, f10, f11)")
    
    start_time = time.time()
    
    try:
        # Симулируем настройку GLV параметров
        if verbose:
            print(f"\n🔧 Настройка GLV параметров...")
            print(f"   λ = 78074008874160198520644763525212887401909906723592317393988542598630163514318")
            print(f"   β = 60197513588986302554485582024885075108884032450952339817679072026166228089408")
            print(f"   Порядок кривой: 115792089237316195423570985008687907852837564279074904382605163141518161494337")
        
        # Симулируем генерацию секретных скаляров (для демонстрации)
        if verbose:
            print(f"\n🎲 Генерация тестовых скаляров...")
            print(f"   k0 = 15 (пример)")
            print(f"   k1 = 11 (пример)")
            print(f"   k = k0 + k1*λ (mod n)")
        
        # Симулируем процесс атаки
        if verbose:
            print(f"\n⚔️ Запуск итеративной атаки...")
        
        result = simulate_dcp_solution(target_bits, verbose)
        
        end_time = time.time()
        attack_time = end_time - start_time
        
        print(f"\n✅ Демонстрация атаки завершена!")
        print(f"   Время выполнения: {attack_time:.2f} секунд")
        print(f"   Восстановлено битов: {result['recovered']:.2f}")
        print(f"   Количество кандидатов: {len(result['scalars'])}")
        
        # Добавляем метаданные
        result['attack_time'] = attack_time
        result['success'] = True
        result['target_bits'] = target_bits
        result['time_zvp'] = attack_time - 0.1  # Симулируем время DCP
        result['demo_mode'] = True
        
        return result
        
    except Exception as e:
        end_time = time.time()
        attack_time = end_time - start_time
        
        print(f"\n❌ Ошибка при демонстрации атаки:")
        print(f"   {str(e)}")
        
        return {
            'success': False,
            'error': str(e),
            'attack_time': attack_time,
            'target_bits': target_bits,
            'demo_mode': True
        }


def print_detailed_results(results):
    """Выводит подробные результаты атаки"""
    print(f"\n📊 Подробные результаты атаки:")
    print(f"   Режим: {'Демонстрация' if results.get('demo_mode') else 'Реальная атака'}")
    print(f"   Успех: {'Да' if results.get('success', False) else 'Нет'}")
    
    if results.get('success', False):
        print(f"   Восстановлено битов: {results.get('recovered', 0):.2f}")
        print(f"   Время атаки ZVP: {results.get('time_zvp', 0):.2f} сек")
        print(f"   Общее время: {results.get('attack_time', 0):.2f} сек")
        
        scalars = results.get('scalars', [])
        print(f"   Найдено кандидатов: {len(scalars)}")
        
        if scalars and len(scalars) <= 10:
            print(f"\n   Кандидаты скаляров (k0, k1) в GLV-SAC представлении:")
            for i, (k0, k1) in enumerate(scalars[:10]):
                k0_str = ''.join(['+' if x == 1 else '-' if x == -1 else '0' for x in k0])
                k1_str = ''.join(['+' if x == 1 else '-' if x == -1 else '0' for x in k1])
                print(f"     {i+1}. k0={k0_str}, k1={k1_str}")
        elif scalars:
            print(f"   Найдено слишком много кандидатов ({len(scalars)}) для отображения")
            
        nguesses = results.get('nguesses', [])
        if nguesses:
            print(f"   Количество предположений по итерациям: {nguesses}")
    else:
        print(f"   Ошибка: {results.get('error', 'Неизвестная ошибка')}")


def save_results_to_file(results, pubkey_x, pubkey_y, target_bits, filename):
    """Сохраняет результаты в JSON файл"""
    full_results = {
        'timestamp': datetime.now().isoformat(),
        'attack_type': 'ZVP-GLV Straus-Shamir (Demo)',
        'curve': 'secp256k1',
        'target_bits': target_bits,
        'pubkey': {
            'x': hex(pubkey_x),
            'y': hex(pubkey_y)
        },
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
    
    filename_with_timestamp = f"{filename[:-5]}_demo_{timestamp}.json"
    filepath = os.path.join(results_dir, filename_with_timestamp)
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(full_results, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Результаты сохранены в файл: {filepath}")
        
    except Exception as e:
        print(f"\n❌ Ошибка при сохранении результатов: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='ДЕМОНСТРАЦИОННАЯ версия атаки ZVP-GLV на Страуса-трюк Шамира',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ВНИМАНИЕ: Это демонстрационная версия!

Примеры использования:
  %(prog)s --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac --bits 4
  %(prog)s --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac --bits 6 --save demo_results

Для реальной атаки используйте zvp_glv_sac.py с SageMath
        """
    )
    
    parser.add_argument(
        '--pubkey',
        type=str,
        required=True,
        help='Публичный ключ в hex формате (130 символов, начинается с 04)'
    )
    
    parser.add_argument(
        '--bits',
        type=int,
        default=4,
        choices=range(2, 11),
        metavar='2-10',
        help='Количество целевых бит для демонстрации (по умолчанию: 4)'
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
    print("🎭 ДЕМОНСТРАЦИЯ АТАКИ ZVP-GLV НА СТРАУСА-ТРЮК ШАМИРА")
    print("=" * 70)
    print(f"⚠️  ВНИМАНИЕ: Это демонстрационная версия скрипта")
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
        
        # Запуск демонстрации атаки
        results = run_demo_attack(pubkey_x, pubkey_y, args.bits, args.verbose)
        
        # Вывод результатов
        print_detailed_results(results)
        
        # Сохранение результатов
        if args.save:
            save_results_to_file(results, pubkey_x, pubkey_y, args.bits, args.save)
        
        # Финальное сообщение
        if results.get('success', False):
            print(f"\n🎉 Демонстрация атаки завершена успешно!")
            recovered_bits = results.get('recovered', 0)
            if recovered_bits > 0:
                print(f"   В реальной атаке было бы восстановлено {recovered_bits:.2f} битов")
            else:
                print(f"   В реальной атаке DCP проблемы могли бы не иметь решений")
        else:
            print(f"\n💥 Демонстрация завершилась с ошибкой")
            return 1
            
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        return 1
    
    print(f"\n📝 Для запуска реальной атаки используйте:")
    print(f"   sage -python zvp_glv_sac.py --pubkey {args.pubkey} --bits {args.bits}")
    print("\n" + "=" * 70)
    return 0


if __name__ == "__main__":
    # Устанавливаем seed для воспроизводимости демонстрации
    random.seed(42)
    sys.exit(main())