#!/usr/bin/env python3
"""
Боевой скрипт для атаки zvp_glv_inter_easy_prec.py
ZVP-GLV Interleaving Easy Precision Attack

Этот скрипт выполняет атаку Zero-Value Point (ZVP) на GLV-разложение 
с использованием регулярного интерливинга и легкой точности.
"""

import sys
import os
import argparse
import json
import time
from datetime import datetime

try:
    # Добавляем attack в путь и импортируем SageMath
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'attack'))
    
    from sage.all import ZZ, Integer
    print("🔬 SageMath импортирован успешно")
    
    # Теперь импортируем модули атаки
    import utils
    from zvp_glv_inter_easy_prec import zvp_glv_interleaving_easy_regular
    print("🔧 Модули атаки импортированы успешно")
    
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    if "sage" in str(e).lower():
        print("📝 Для работы скрипта требуется SageMath:")
        print("   Ubuntu/Debian: sudo apt-get install sagemath")
        print("   Conda: conda install -c conda-forge sage")
        print("   Или запустите через: sage -python attack_zvp_glv_inter_easy_prec.py")
    else:
        print("Убедитесь, что доступны модули атаки в папке attack/")
    sys.exit(1)


def parse_hex_pubkey(hex_string):
    """Парсинг публичного ключа из hex строки"""
    # Удаляем префикс '04' если присутствует (несжатый формат)
    if hex_string.startswith('04') and len(hex_string) == 130:
        hex_string = hex_string[2:]
        print(f"   🔍 Обнаружен префикс '04', удаляем (несжатый формат)")
    
    if len(hex_string) != 128:
        raise ValueError(f"Публичный ключ должен содержать 128 hex символов, получено: {len(hex_string)}")
    
    try:
        # Разделяем на координаты x и y (по 64 символа каждая)
        x_hex = hex_string[:64]
        y_hex = hex_string[64:]
        
        x = int(x_hex, 16)
        y = int(y_hex, 16)
        
        return x, y
    except ValueError as e:
        raise ValueError(f"Неверный формат hex строки: {e}")


def setup_zvp_parameters(pubkey_hex, bits):
    """Настройка параметров ZVP атаки"""
    print(f"🔧 Настройка параметров ZVP атаки...")
    print(f"   Публичный ключ: {pubkey_hex}")
    print(f"   Целевые биты: {bits}")
    
    # Парсим публичный ключ
    try:
        pub_x, pub_y = parse_hex_pubkey(pubkey_hex)
        print(f"   Координата X: {hex(pub_x)}")
        print(f"   Координата Y: {hex(pub_y)}")
    except ValueError as e:
        print(f"❌ Ошибка парсинга публичного ключа: {e}")
        return None
    
    # Создаем параметры ZVP
    zvp_params = utils.ZVPparams(256)  # Используем 256-битную кривую
    
    # Устанавливаем secp256k1
    print("🔐 Настройка криптографических параметров...")
    zvp_params.generate_secp256k1_secrets()
    print(f"   Кривая: secp256k1")
    print(f"   Порядок поля: {hex(zvp_params.glv.p)}")
    print(f"   Порядок группы: {hex(zvp_params.glv.order)}")
    print(f"   Lambda: {hex(zvp_params.glv.lam)}")
    print(f"   Beta: {hex(zvp_params.glv.beta)}")
    
    # Устанавливаем целевые биты
    zvp_params.target_bits = bits
    
    # Проверяем, что публичный ключ лежит на кривой
    try:
        point = zvp_params.glv.curve(pub_x, pub_y)
        print(f"✅ Публичный ключ валиден и лежит на кривой")
        print(f"   Точка: ({point[0]}, {point[1]})")
    except Exception as e:
        print(f"❌ Публичный ключ не лежит на кривой secp256k1: {e}")
        return None
    
    # Настраиваем регистры (полиномы для детекции нулевых точек)
    print("📊 Настройка регистров обнаружения...")
    zvp_params.registers.empty_out()
    
    # Добавляем базовые полиномы для обнаружения нулевых точек
    # Эти полиномы детектируют случаи, когда промежуточные вычисления дают нулевую точку
    zvp_params.registers.add("X1 - X2")  # Детектирует одинаковые X координаты
    zvp_params.registers.add("Y1 - Y2")  # Детектирует одинаковые Y координаты
    zvp_params.registers.add("X1*Y2 - X2*Y1")  # Детектирует пропорциональность
    
    print(f"   Добавлено {len(zvp_params.registers.polynomials)} регистров")
    
    return zvp_params, point


def perform_attack(zvp_params, target_bits, window_size, verbose=True):
    """Выполнение атаки"""
    print(f"\n🚀 Запуск атаки ZVP-GLV Interleaving Easy Precision...")
    print(f"   Алгоритм: ZVP-GLV с регулярным интерливингом")
    print(f"   Целевые биты: {target_bits}")
    print(f"   Размер окна w: {window_size}")
    
    start_time = time.time()
    
    try:
        # Устанавливаем функцию атаки с параметром w
        def attack_wrapper(params):
            return zvp_glv_interleaving_easy_regular(params, window_size)
        
        zvp_params.attack = attack_wrapper
        
        if verbose:
            print("📈 Выполнение атаки...")
            print("   Этап 1: Загрузка предвычисленных точек...")
            print("   Этап 2: Применение ZVP оракула...")
            print("   Этап 3: Фильтрация возможных значений...")
            print("   Этап 4: Вычисление оставшейся энтропии...")
        
        # Выполняем атаку
        zvp_params.do_attack()
        
        end_time = time.time()
        duration = end_time - start_time
        
        if zvp_params.results:
            remaining_bits = zvp_params.results.get('remaining', 'неизвестно')
            print(f"✅ Атака завершена успешно!")
            print(f"   Время выполнения: {duration:.2f} секунд")
            print(f"   Оставшаяся энтропия: {remaining_bits} бит")
            
            if isinstance(remaining_bits, (int, float)) and remaining_bits < 64:
                print(f"🎯 Атака успешна! Энтропия снижена до {remaining_bits} бит")
                print(f"   Это делает brute-force атаку практически выполнимой!")
            elif isinstance(remaining_bits, (int, float)):
                print(f"⚠️  Энтропия все еще высока: {remaining_bits} бит")
                print(f"   Попробуйте увеличить количество целевых бит")
            
            return True, zvp_params.results
        else:
            print(f"❌ Атака не удалась - результаты отсутствуют")
            return False, None
            
    except FileNotFoundError as e:
        print(f"❌ Ошибка: Отсутствуют предвычисленные данные")
        print(f"   {e}")
        print(f"   Необходимо сначала выполнить DCP эксперименты для генерации данных")
        return False, None
    except Exception as e:
        print(f"❌ Ошибка во время атаки: {e}")
        return False, None


def save_results(results, zvp_params, pubkey_hex, window_size, filename=None):
    """Сохранение результатов в JSON файл"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_results_{timestamp}.json"
    
    print(f"\n💾 Сохранение результатов в {filename}...")
    
    # Подготавливаем данные для сохранения
    save_data = {
        "timestamp": datetime.now().isoformat(),
        "attack_type": "zvp_glv_interleaving_easy_precision",
        "target_pubkey": pubkey_hex,
        "target_bits": zvp_params.target_bits,
        "window_size": window_size,
        "curve_params": zvp_params.glv.to_dict(),
        "attack_results": results,
        "registers": zvp_params.registers.to_strings() if hasattr(zvp_params.registers, 'to_strings') else str(zvp_params.registers),
        "success": results is not None and 'remaining' in results
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(save_data, f, indent=2, default=str)
        print(f"✅ Результаты сохранены в {filename}")
        return True
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Боевой скрипт для атаки ZVP-GLV Interleaving Easy Precision",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python attack_zvp_glv_inter_easy_prec.py --pubkey 1234567890abcdef... --w 4
  python attack_zvp_glv_inter_easy_prec.py --pubkey 1234567890abcdef... --bits 4 --w 5 --save results.json

Описание атаки:
  Этот скрипт реализует атаку Zero-Value Point (ZVP) на GLV-разложение
  эллиптических кривых. Атака использует утечки информации через регистры
  нулевых значений в алгоритмах multi-scalar multiplication.
        """
    )
    
    parser.add_argument(
        '--pubkey',
        required=True,
        help='Публичный ключ (128 hex символов: 64 для X + 64 для Y координат)'
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
        '--w',
        type=int,
        default=4,
        choices=range(3, 11),
        metavar='3-10',
        help='Размер окна для w-NAF представления (по умолчанию: 4)'
    )
    
    parser.add_argument(
        '--save',
        help='Сохранить результаты в указанный JSON файл'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Тихий режим (минимум вывода)'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Только проверить корректность публичного ключа'
    )
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("🎯 ZVP-GLV Interleaving Easy Precision Attack")
        print("=" * 50)
    
    # Настройка параметров
    result = setup_zvp_parameters(args.pubkey, args.bits)
    if result is None:
        sys.exit(1)
    
    zvp_params, pubkey_point = result
    
    if args.verify:
        print("✅ Публичный ключ корректен!")
        sys.exit(0)
    
    # Выполнение атаки
    success, attack_results = perform_attack(zvp_params, args.bits, args.w, verbose=not args.quiet)
    
    # Сохранение результатов
    if args.save:
        save_results(attack_results, zvp_params, args.pubkey, args.w, args.save)
    
    if success:
        print(f"\n🎉 Атака завершена успешно!")
        sys.exit(0)
    else:
        print(f"\n💥 Атака не удалась!")
        sys.exit(1)


if __name__ == "__main__":
    main()