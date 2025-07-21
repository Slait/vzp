#!/usr/bin/env python3
"""
Вспомогательная утилита для проверки валидности публичного ключа secp256k1
Не требует SageMath для работы

Использование:
    python3 pubkey_validator.py <pubkey_hex>

Пример:
    python3 pubkey_validator.py 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac
"""

import sys


def parse_pubkey(pubkey_hex):
    """
    Парсит публичный ключ из hex строки
    
    Args:
        pubkey_hex (str): Публичный ключ в hex формате
        
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
        
        x = int('0x' + x_hex, 16)
        y = int('0x' + y_hex, 16)
        
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
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    
    # Проверяем, что координаты в допустимом диапазоне
    if not (0 <= x < p) or not (0 <= y < p):
        return False
    
    # Проверяем уравнение кривой
    left_side = (y * y) % p
    right_side = (x * x * x + 7) % p
    
    return left_side == right_side


def main():
    if len(sys.argv) != 2:
        print("Использование: python3 pubkey_validator.py <pubkey_hex>")
        print("\nПример:")
        print("python3 pubkey_validator.py 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac")
        return 1
    
    pubkey_hex = sys.argv[1]
    
    print("🔍 Проверка публичного ключа secp256k1")
    print("=" * 50)
    
    try:
        # Парсинг публичного ключа
        print(f"📋 Парсинг ключа: {pubkey_hex}")
        x, y = parse_pubkey(pubkey_hex)
        
        print(f"✅ Формат корректный")
        print(f"   Длина: {len(pubkey_hex)} символов")
        print(f"   Префикс: {pubkey_hex[:2]}")
        
        # Отображение координат
        print(f"\n📐 Координаты точки:")
        print(f"   X: {hex(x)}")
        print(f"   Y: {hex(y)}")
        
        # Проверка что точка на кривой
        print(f"\n🧮 Проверка уравнения кривой y² = x³ + 7 (mod p)...")
        if validate_point_on_curve(x, y):
            print(f"✅ Точка корректно лежит на кривой secp256k1")
            print(f"\n🎯 Ключ готов для использования в атаке ZVP-GLV!")
        else:
            print(f"❌ Точка НЕ лежит на кривой secp256k1")
            return 1
            
    except ValueError as e:
        print(f"❌ Ошибка: {e}")
        return 1
    
    print("\n" + "=" * 50)
    return 0


if __name__ == "__main__":
    sys.exit(main())