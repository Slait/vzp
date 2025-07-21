#!/usr/bin/env python3
"""
Скрипт для проверки правильности восстановления битов приватного ключа
из результатов атаки ZVP-GLV на кривой secp256k1

Использование:
    python3 key_checker.py --private-key <hex> --candidates <json_file>
    python3 key_checker.py --private-key <hex> --manual-check --k0 "1,1,-1,1" --k1 "1,-1,1,1"

Пример:
    python3 key_checker.py --private-key abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 --candidates attack/results/test_demo_demo_20250721_140131.json
"""

import sys
import argparse
import json
import hashlib


# Константы secp256k1
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_LAMBDA = 0xAC9C52B33FA3CF1F5AD9E3FD77ED9BA4A880B9FC8EC739C2E0CFC810B51283CE88328B42


def mod_inverse(a, m):
    """Вычисляет модульную обратную величину a^(-1) mod m"""
    if a < 0:
        a = (a % m + m) % m
    
    # Расширенный алгоритм Евклида
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Модульная обратная не существует")
    return (x % m + m) % m


def point_add(px, py, qx, qy):
    """Сложение точек на кривой secp256k1"""
    if px is None:  # O + Q = Q
        return qx, qy
    if qx is None:  # P + O = P
        return px, py
    
    if px == qx:
        if py == qy:
            # Удвоение точки
            s = (3 * px * px * mod_inverse(2 * py, SECP256K1_P)) % SECP256K1_P
        else:
            # P + (-P) = O
            return None, None
    else:
        # Обычное сложение
        s = ((qy - py) * mod_inverse(qx - px, SECP256K1_P)) % SECP256K1_P
    
    rx = (s * s - px - qx) % SECP256K1_P
    ry = (s * (px - rx) - py) % SECP256K1_P
    
    return rx, ry


def point_multiply(k, px=SECP256K1_GX, py=SECP256K1_GY):
    """Умножение точки на скаляр методом двойного и сложения"""
    if k == 0:
        return None, None
    
    result_x, result_y = None, None
    addend_x, addend_y = px, py
    
    while k:
        if k & 1:
            result_x, result_y = point_add(result_x, result_y, addend_x, addend_y)
        addend_x, addend_y = point_add(addend_x, addend_y, addend_x, addend_y)
        k >>= 1
    
    return result_x, result_y


def private_key_to_public_key(private_key):
    """Преобразует приватный ключ в публичный ключ (несжатый формат)"""
    private_key = private_key % SECP256K1_N
    
    if private_key == 0:
        raise ValueError("Приватный ключ не может быть 0")
    
    pub_x, pub_y = point_multiply(private_key)
    
    if pub_x is None:
        raise ValueError("Ошибка при вычислении публичного ключа")
    
    # Возвращаем в несжатом формате
    return f"04{pub_x:064x}{pub_y:064x}"


def glv_sac_to_value(k0_bits, k1_bits):
    """
    Преобразует биты GLV-SAC в числовые значения k0 и k1
    
    Args:
        k0_bits: список битов k0 (от старшего к младшему)
        k1_bits: список битов k1 (от старшего к младшему)
    
    Returns:
        tuple: (k0_value, k1_value)
    """
    if len(k0_bits) != len(k1_bits):
        raise ValueError("Длины k0_bits и k1_bits должны совпадать")
    
    t = len(k0_bits)
    
    # Преобразуем биты в числа (знаковое представление)
    k0 = sum(k0_bits[i] * (2 ** (t-1-i)) for i in range(t))
    k1 = sum(k1_bits[i] * (2 ** (t-1-i)) for i in range(t))
    
    return k0, k1


def recover_partial_private_key(k0_bits, k1_bits):
    """
    Восстанавливает частичный приватный ключ из битов GLV-SAC
    
    Args:
        k0_bits: список битов k0 (от старшего к младшему)  
        k1_bits: список битов k1 (от старшего к младшему)
    
    Returns:
        tuple: (partial_key, k0_value, k1_value, bit_length)
    """
    k0, k1 = glv_sac_to_value(k0_bits, k1_bits)
    
    # Вычисляем частичный ключ: d = k0 + k1 * λ (mod n)
    partial_key = (k0 + k1 * SECP256K1_LAMBDA) % SECP256K1_N
    
    return partial_key, k0, k1, len(k0_bits)


def get_key_range(partial_key, bit_length):
    """
    Вычисляет диапазон возможных приватных ключей
    
    Args:
        partial_key: восстановленные верхние биты
        bit_length: количество восстановленных битов
    
    Returns:
        tuple: (min_key, max_key)
    """
    # Сдвигаем частичный ключ в позицию верхних битов
    shift = 256 - 2 * bit_length  # Умножаем на 2 потому что GLV дает 2t битов из t битов
    
    min_key = partial_key << shift
    max_key = ((partial_key + 1) << shift) - 1
    
    return min_key, max_key


def check_candidate(k0_bits, k1_bits, target_private_key, verbose=True):
    """
    Проверяет кандидата битов против известного приватного ключа
    
    Args:
        k0_bits: список битов k0
        k1_bits: список битов k1  
        target_private_key: правильный приватный ключ (int)
        verbose: подробный вывод
    
    Returns:
        dict: результат проверки
    """
    try:
        partial_key, k0, k1, bit_length = recover_partial_private_key(k0_bits, k1_bits)
        min_key, max_key = get_key_range(partial_key, bit_length)
        
        # Проверяем попадает ли целевой ключ в диапазон
        in_range = min_key <= target_private_key <= max_key
        
        # Вычисляем публичные ключи для сравнения
        target_pubkey = private_key_to_public_key(target_private_key)
        partial_pubkey = private_key_to_public_key(partial_key)
        
        result = {
            'k0_bits': k0_bits,
            'k1_bits': k1_bits,
            'k0_value': k0,
            'k1_value': k1,
            'partial_key': partial_key,
            'bit_length': bit_length,
            'effective_bits': 2 * bit_length,
            'min_key': min_key,
            'max_key': max_key,
            'target_in_range': in_range,
            'target_pubkey': target_pubkey,
            'partial_pubkey': partial_pubkey,
            'success': in_range
        }
        
        if verbose:
            print(f"\n🔍 Проверка кандидата:")
            print(f"   k0 = {k0_bits} → {k0}")
            print(f"   k1 = {k1_bits} → {k1}")
            print(f"   Частичный ключ: {hex(partial_key)}")
            print(f"   Эффективных битов: {2 * bit_length}")
            print(f"   Диапазон: {hex(min_key)} - {hex(max_key)}")
            print(f"   Целевой ключ в диапазоне: {'✅' if in_range else '❌'}")
            if in_range:
                print(f"   🎉 СОВПАДЕНИЕ! Биты восстановлены правильно!")
            else:
                print(f"   💥 Не совпадает. Эти биты неверные.")
        
        return result
        
    except Exception as e:
        if verbose:
            print(f"\n❌ Ошибка при проверке кандидата: {e}")
        return {'success': False, 'error': str(e)}


def parse_candidates_from_json(json_file):
    """Извлекает кандидатов из JSON файла результатов атаки"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Пытаемся найти кандидатов в разных местах структуры
        candidates = None
        
        if 'results' in data and 'scalars' in data['results']:
            candidates = data['results']['scalars']
        elif 'scalars' in data:
            candidates = data['scalars']
        elif isinstance(data, list) and len(data) > 0:
            # Может быть список результатов
            for item in data:
                if 'scalars' in item:
                    candidates = item['scalars']
                    break
        
        if candidates is None:
            raise ValueError("Не найдены кандидаты в JSON файле")
        
        return candidates
        
    except Exception as e:
        raise ValueError(f"Ошибка при чтении JSON файла: {e}")


def parse_manual_bits(bits_string):
    """Парсит строку битов вида '1,1,-1,1' в список чисел"""
    try:
        return [int(x.strip()) for x in bits_string.split(',')]
    except ValueError:
        raise ValueError(f"Неверный формат битов: {bits_string}. Ожидается '1,1,-1,1'")


def main():
    parser = argparse.ArgumentParser(
        description='Проверка правильности восстановления битов приватного ключа',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:

1. Проверка из файла результатов:
   python3 key_checker.py --private-key abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 --candidates results.json

2. Ручная проверка кандидата:
   python3 key_checker.py --private-key abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 --manual-check --k0 "1,1,-1,1" --k1 "1,-1,1,1"

3. Проверка всех кандидатов подробно:
   python3 key_checker.py --private-key abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 --candidates results.json --verbose
        """
    )
    
    parser.add_argument(
        '--private-key',
        type=str,
        required=True,
        help='Правильный приватный ключ в hex формате (64 hex символа)'
    )
    
    parser.add_argument(
        '--candidates',
        type=str,
        help='JSON файл с результатами атаки'
    )
    
    parser.add_argument(
        '--manual-check',
        action='store_true',
        help='Ручная проверка одного кандидата'
    )
    
    parser.add_argument(
        '--k0',
        type=str,
        help='Биты k0 в формате "1,1,-1,1" (для ручной проверки)'
    )
    
    parser.add_argument(
        '--k1',
        type=str,
        help='Биты k1 в формате "1,-1,1,1" (для ручной проверки)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Подробный вывод для каждого кандидата'
    )
    
    args = parser.parse_args()
    
    # Валидация параметров
    if not args.candidates and not args.manual_check:
        print("❌ Ошибка: укажите --candidates или используйте --manual-check")
        return 1
    
    if args.manual_check and (not args.k0 or not args.k1):
        print("❌ Ошибка: для ручной проверки нужны --k0 и --k1")
        return 1
    
    print("=" * 70)
    print("🔍 ПРОВЕРКА ПРАВИЛЬНОСТИ ВОССТАНОВЛЕНИЯ БИТОВ ПРИВАТНОГО КЛЮЧА")
    print("=" * 70)
    
    try:
        # Парсим приватный ключ
        private_key_str = args.private_key.strip()
        if private_key_str.startswith('0x'):
            private_key = int(private_key_str, 16)
        elif len(private_key_str) == 64:
            private_key = int(private_key_str, 16)
        else:
            try:
                private_key = int(private_key_str, 16)
            except ValueError:
                private_key = int(private_key_str)
        
        if not (1 <= private_key < SECP256K1_N):
            raise ValueError("Приватный ключ вне допустимого диапазона")
        
        print(f"\n🔑 Целевой приватный ключ:")
        print(f"   Hex: {hex(private_key)}")
        print(f"   Битов: {private_key.bit_length()}")
        
        # Вычисляем соответствующий публичный ключ
        target_pubkey = private_key_to_public_key(private_key)
        print(f"   Публичный ключ: {target_pubkey}")
        
        if args.manual_check:
            # Ручная проверка одного кандидата
            print(f"\n🧪 Ручная проверка кандидата:")
            
            k0_bits = parse_manual_bits(args.k0)
            k1_bits = parse_manual_bits(args.k1)
            
            result = check_candidate(k0_bits, k1_bits, private_key, verbose=True)
            
            if result['success']:
                print(f"\n🎉 УСПЕХ! Биты восстановлены правильно!")
                return 0
            else:
                print(f"\n💥 НЕУДАЧА! Биты восстановлены неправильно.")
                return 1
        
        else:
            # Проверка из файла кандидатов
            print(f"\n📂 Загрузка кандидатов из файла: {args.candidates}")
            
            candidates = parse_candidates_from_json(args.candidates)
            print(f"   Найдено кандидатов: {len(candidates)}")
            
            correct_candidates = []
            
            for i, candidate in enumerate(candidates):
                if isinstance(candidate, list) and len(candidate) == 2:
                    k0_bits, k1_bits = candidate
                else:
                    print(f"   ⚠️ Пропускаю кандидата {i+1}: неверный формат")
                    continue
                
                print(f"\n📊 Кандидат {i+1}/{len(candidates)}:")
                
                result = check_candidate(k0_bits, k1_bits, private_key, verbose=args.verbose)
                
                if result['success']:
                    correct_candidates.append((i+1, result))
                    if not args.verbose:
                        print(f"   ✅ СОВПАДЕНИЕ!")
            
            # Итоговый отчет
            print(f"\n" + "=" * 70)
            print(f"📈 ИТОГОВЫЙ ОТЧЕТ:")
            print(f"   Всего кандидатов: {len(candidates)}")
            print(f"   Правильных кандидатов: {len(correct_candidates)}")
            print(f"   Процент успеха: {len(correct_candidates)/len(candidates)*100:.1f}%")
            
            if correct_candidates:
                print(f"\n🎯 ПРАВИЛЬНЫЕ КАНДИДАТЫ:")
                for idx, result in correct_candidates:
                    print(f"   #{idx}: k0={result['k0_bits']}, k1={result['k1_bits']}")
                    print(f"        Эффективных битов: {result['effective_bits']}")
                
                print(f"\n🎉 АТАКА УСПЕШНА! Найдены правильные биты!")
                return 0
            else:
                print(f"\n💥 НИ ОДИН КАНДИДАТ НЕ ПОДОШЕЛ!")
                print(f"   Возможные причины:")
                print(f"   - Неправильный приватный ключ")
                print(f"   - Атака не смогла найти правильные биты")
                print(f"   - Ошибка в формате данных")
                return 1
        
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())