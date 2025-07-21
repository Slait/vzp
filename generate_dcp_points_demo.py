#!/usr/bin/env python3
"""
ДЕМО-версия генератора предвычисленных DCP точек для ZVP-GLV атаки
Симулирует процесс генерации точек без SageMath для демонстрации
"""

import sys
import os
import argparse
import json
import time
import random
from datetime import datetime


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


def validate_secp256k1_point(x, y):
    """Базовая проверка точки на кривой secp256k1"""
    # secp256k1: y^2 = x^3 + 7 (mod p)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    
    try:
        left = (y * y) % p
        right = (x * x * x + 7) % p
        return left == right
    except:
        return False


def get_wnaf_values(w):
    """Получение всех возможных w-NAF значений для окна w"""
    # Симуляция функции all_rwnaf_values из inter_easy
    max_val = (1 << w) - 1  # 2^w - 1
    values = []
    
    # Добавляем положительные нечетные значения
    for i in range(1, max_val + 1, 2):
        values.append(i)
    
    # Добавляем отрицательные
    negative_values = [-v for v in values]
    
    return negative_values + values


def simulate_dcp_experiments(pubkey_x, pubkey_y, w, polynomial_index, num_experiments, verbose=True):
    """Симуляция DCP экспериментов"""
    if verbose:
        print(f"\n🧪 СИМУЛЯЦИЯ: Генерация DCP экспериментов...")
        print(f"   Размер окна w: {w}")
        print(f"   Полином: #{polynomial_index}")
        print(f"   Количество экспериментов: {num_experiments}")
    
    # Получаем w-NAF значения
    wnaf_values = get_wnaf_values(w)
    if verbose:
        print(f"   w-NAF значения: {wnaf_values}")
    
    results_list = []
    total_combinations = len(wnaf_values) * len(wnaf_values)
    
    if verbose:
        print(f"   Общее количество комбинаций: {total_combinations}")
        print(f"   Запуск симуляции...")
    
    processed = 0
    successful = 0
    
    # Инициализируем генератор случайных чисел для воспроизводимости
    random.seed(hash((pubkey_x, pubkey_y, w, polynomial_index)) % (2**32))
    
    for w0 in wnaf_values:
        for w1 in wnaf_values:
            # Симулируем время выполнения
            if verbose and processed % 5 == 0:
                time.sleep(0.01)  # Небольшая задержка для реализма
            
            # Симулируем успех эксперимента (зависит от параметров)
            success_probability = 0.1 + (abs(w0) + abs(w1)) * 0.01  # Больше вероятность для больших значений
            success_probability = min(success_probability, 0.8)  # Максимум 80%
            
            if random.random() < success_probability:
                # Генерируем случайную "найденную" точку
                point_x = random.randint(1, 2**255)
                point_y = random.randint(1, 2**255)
                
                result_dict = {
                    "k0": int(w0), "k1": int(w1), "k": -1,
                    "result": {
                        "recovered": 1,
                        "point": [point_x, point_y],
                        "time_zvp": random.uniform(0.1, 2.0),
                        "nguesses": 0
                    }
                }
                successful += 1
            else:
                # Неудачный эксперимент
                result_dict = {
                    "k0": int(w0), "k1": int(w1), "k": -1,
                    "result": {
                        "recovered": 0,
                        "point": [],
                        "time_zvp": random.uniform(0.05, 1.0),
                        "nguesses": 0
                    }
                }
            
            results_list.append(result_dict)
            processed += 1
            
            # Показываем прогресс каждые 10%
            if verbose and processed % max(1, total_combinations // 10) == 0:
                progress = (processed / total_combinations) * 100
                print(f"   Прогресс: {progress:.1f}% ({processed}/{total_combinations}), найдено точек: {successful}")
            
            # Ограничиваем количество экспериментов если задано
            if num_experiments > 0 and len(results_list) >= num_experiments:
                break
        
        if num_experiments > 0 and len(results_list) >= num_experiments:
            break
    
    if verbose:
        print(f"✅ Завершено экспериментов: {len(results_list)}")
        print(f"   Успешных (найдены точки): {successful}")
        print(f"   Процент успеха: {(successful/len(results_list)*100):.1f}%")
    
    return results_list


def save_dcp_results(results_list, w, polynomial_index, pubkey_hex, timestamp=None):
    """Сохранение результатов DCP экспериментов"""
    if not os.path.exists("attack/results"):
        os.makedirs("attack/results")
    
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
    
    # Формируем имя файла согласно формату проекта
    filename = f"attack/results/interleaving_dcp_experiment_256_demo_{timestamp}.json"
    
    print(f"💾 Сохранение результатов в {filename}...")
    
    # Подготавливаем метаданные
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "experiment_type": "interleaving_dcp_experiment_demo",
        "window_size": w,
        "polynomial_index": polynomial_index,
        "curve": "secp256k1",
        "pubkey": pubkey_hex,
        "total_experiments": len(results_list),
        "successful_experiments": sum(1 for r in results_list if r["result"]["recovered"]),
        "note": "This is a DEMO simulation without real cryptographic computations"
    }
    
    # Сохраняем с метаданными
    final_data = {
        "metadata": metadata,
        "results": results_list
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(final_data, f, indent=2, default=str)
        print(f"✅ Результаты сохранены: {len(results_list)} экспериментов")
        return filename
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        return None


def simulate_remapped_points(pubkey_x, pubkey_y, w, dcp_results_file, polynomial_index, verbose=True):
    """Симуляция remapped точек из DCP результатов"""
    if verbose:
        print(f"\n🔄 СИМУЛЯЦИЯ: Генерация remapped точек для w={w}...")
    
    # Загружаем результаты DCP экспериментов
    try:
        with open(dcp_results_file, 'r') as f:
            dcp_data = json.load(f)
        
        if "results" in dcp_data:
            results = dcp_data["results"]
        else:
            results = dcp_data  # Старый формат
            
    except Exception as e:
        print(f"❌ Ошибка загрузки DCP результатов: {e}")
        return None
    
    if verbose:
        print(f"   Загружено DCP результатов: {len(results)}")
    
    # Собираем все найденные точки
    unique_points = set()
    for result in results:
        if result["result"]["point"]:
            point_x, point_y = result["result"]["point"]
            unique_points.add((point_x, point_y))
    
    if verbose:
        print(f"   Уникальных точек найдено: {len(unique_points)}")
    
    if len(unique_points) == 0:
        print("❌ Не найдено точек для remapping")
        return None
    
    # Симуляция remapping точек
    all_pos_scalars = get_wnaf_values(w)
    point_list = []
    
    if verbose:
        print(f"   Выполняется remapping для w-NAF значений: {all_pos_scalars}")
    
    # Генерируем случайные scalars для каждой точки
    random.seed(hash((pubkey_x, pubkey_y, w, polynomial_index)) % (2**32))
    
    for i, (point_x, point_y) in enumerate(unique_points):
        scalars = []
        
        # Симулируем, что некоторые комбинации w0, w1 дают zero
        num_scalars = random.randint(1, min(8, len(all_pos_scalars)))
        selected_scalars = random.sample(all_pos_scalars, num_scalars)
        
        for w0 in selected_scalars:
            w1 = random.choice(all_pos_scalars)
            scalars.append((int(w0), int(w1)))
        
        point_list.append([(int(point_x), int(point_y)), scalars])
        
        if verbose and (i + 1) % 10 == 0:
            print(f"   Обработано точек: {i + 1}/{len(unique_points)}")
    
    # Формируем строковое представление регистра (симуляция)
    register_strings = [
        ["X1 + X2", "X1 + X2"],
        ["-X1^4 + 6*X1^3*X2 - 7*X1^2*X2^2 + 2*X1*X2^3 - X2^4 + 8*X1*B", 
         "2*X1^3 - 4*X1^2*X2 + 2*X1*X2^2 - Y1^2 + 2*Y1*Y2 - Y2^2"],
        ["-X1^4 + 4*X1^3*X2 + 6*X1^2*X2^2 + 4*X1*X2^3 - X2^4 + 24*X1*B + 24*X2*B", 
         "2*X1^4 + 4*X1^3*X2 + 6*X1^2*X2^2 + 4*X1*X2^3 + 2*X2^4 - 3*X1*Y1^2 - 3*Y1^2*X2 - 6*X1*Y1*Y2 - 6*Y1*X2*Y2 - 3*X1*Y2^2 - 3*X2*Y2^2"]
    ]
    
    register_index = polynomial_index % len(register_strings)
    
    # Формируем данные для сохранения
    to_save = {
        "register": [register_strings[register_index]], 
        "points": point_list
    }
    
    if verbose:
        print(f"✅ Remapping завершен: {len(point_list)} точек")
    
    return to_save


def save_remapped_points(remapped_data, w):
    """Сохранение remapped точек в формате проекта"""
    filename = f"attack/results/interleaving_secp256k1_remapped_{w}_demo.json"
    
    print(f"💾 Сохранение remapped точек в {filename}...")
    
    # Пытаемся загрузить существующие данные
    try:
        with open(filename, 'r') as f:
            existing_data = json.load(f)
    except FileNotFoundError:
        existing_data = []
    
    # Добавляем новые данные
    existing_data.append(remapped_data)
    
    try:
        with open(filename, 'w') as f:
            json.dump(existing_data, f, indent=2)
        print(f"✅ Remapped точки сохранены: {len(remapped_data['points'])} точек")
        return filename
    except Exception as e:
        print(f"❌ Ошибка сохранения remapped точек: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="ДЕМО-генератор предвычисленных DCP точек (симуляция без SageMath)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎭 ДЕМО РЕЖИМ - Симуляция без реальных криптографических вычислений

Примеры использования:
  # Быстрая симуляция для w=4
  python3 generate_dcp_points_demo.py --pubkey YOUR_KEY --w 4 --experiments 50
  
  # Симуляция для нескольких окон
  python3 generate_dcp_points_demo.py --pubkey YOUR_KEY --w 3 4 5 --experiments 100
  
  # Тихий режим
  python3 generate_dcp_points_demo.py --pubkey YOUR_KEY --w 4 --quiet

Этот скрипт создает демо-файлы:
  - attack/results/interleaving_dcp_experiment_256_demo_TIMESTAMP.json 
  - attack/results/interleaving_secp256k1_remapped_W_demo.json
  
ВНИМАНИЕ: Это симуляция! Для реальной атаки используйте generate_dcp_points.py с SageMath.
        """
    )
    
    parser.add_argument(
        '--pubkey',
        required=True,
        help='Публичный ключ (128 hex символов или 130 с префиксом "04")'
    )
    
    parser.add_argument(
        '--w',
        type=int,
        nargs='+',
        default=[4],
        choices=range(3, 11),
        help='Размеры окон для w-NAF (3-10, по умолчанию: 4)'
    )
    
    parser.add_argument(
        '--polynomial',
        type=int,
        default=0,
        choices=range(0, 13),
        help='Индекс полинома secp256k1 (0-12, по умолчанию: 0)'
    )
    
    parser.add_argument(
        '--experiments',
        type=int,
        default=100,
        help='Количество DCP экспериментов для симуляции (по умолчанию: 100)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Тихий режим (минимум вывода)'
    )
    
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    if verbose:
        print("🎭 ДЕМО: Генератор предвычисленных DCP точек")
        print("=" * 50)
        print("⚠️  ВНИМАНИЕ: Это симуляция без реальных криптографических вычислений!")
        print("📝 Для реальной атаки используйте generate_dcp_points.py с SageMath")
        print()
    
    # Парсинг публичного ключа
    try:
        pub_x, pub_y = parse_hex_pubkey(args.pubkey)
        if verbose:
            print(f"🔧 Публичный ключ:")
            print(f"   X: {hex(pub_x)}")
            print(f"   Y: {hex(pub_y)}")
            
        # Проверяем валидность (базовая)
        if validate_secp256k1_point(pub_x, pub_y):
            if verbose:
                print(f"✅ Публичный ключ прошел базовую проверку secp256k1")
        else:
            print(f"⚠️  Публичный ключ не прошел базовую проверку (может быть ложной)")
            
    except ValueError as e:
        print(f"❌ Ошибка парсинга публичного ключа: {e}")
        sys.exit(1)
    
    # Обрабатываем каждый размер окна
    for w in args.w:
        if verbose:
            print(f"\n🚀 СИМУЛЯЦИЯ для размера окна w={w}")
        
        # Симуляция DCP экспериментов
        if verbose:
            print(f"📊 Этап 1: Симуляция DCP экспериментов")
        
        start_time = time.time()
        results = simulate_dcp_experiments(
            pub_x, pub_y, w, args.polynomial, 
            args.experiments, verbose
        )
        duration = time.time() - start_time
        
        if verbose:
            print(f"   Время симуляции: {duration:.1f} секунд")
        
        # Сохраняем DCP результаты
        dcp_file = save_dcp_results(results, w, args.polynomial, args.pubkey)
        if not dcp_file:
            print(f"❌ Не удалось сохранить DCP результаты для w={w}")
            continue
        
        # Симуляция remapped точек
        if verbose:
            print(f"🔄 Этап 2: Симуляция remapped точек")
        
        start_time = time.time()
        remapped_data = simulate_remapped_points(
            pub_x, pub_y, w, dcp_file, args.polynomial, verbose
        )
        duration = time.time() - start_time
        
        if not remapped_data:
            print(f"❌ Не удалось создать remapped точки для w={w}")
            continue
            
        if verbose:
            print(f"   Время симуляции remapping: {duration:.1f} секунд")
        
        # Сохраняем remapped точки
        remapped_file = save_remapped_points(remapped_data, w)
        if not remapped_file:
            print(f"❌ Не удалось сохранить remapped точки для w={w}")
            continue
        
        if verbose:
            print(f"✅ Симуляция завершена для w={w}")
            print(f"   DCP файл: {dcp_file}")
            print(f"   Remapped файл: {remapped_file}")
    
    if verbose:
        print(f"\n🎉 Симуляция генерации предвычисленных точек завершена!")
        print(f"🎭 Созданы демо-файлы для тестирования структуры данных")
        print(f"⚠️  Для реальной атаки замените на generate_dcp_points.py с SageMath")


if __name__ == "__main__":
    main()