#!/usr/bin/env python3
"""
Генератор предвычисленных DCP точек для ZVP-GLV атаки
Создает точки, необходимые для "Этап 1: Загрузка предвычисленных точек..."

Использует модули из папки attack/ для генерации DCP точек согласно
алгоритму из zvp_glv_inter_easy_prec.py
"""

import sys
import os
import argparse
import json
import time
from datetime import datetime
from copy import deepcopy

try:
    # Добавляем attack в путь и импортируем SageMath
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'attack'))
    
    from sage.all import ZZ, Integer
    print("🔬 SageMath импортирован успешно")
    
    # Теперь импортируем модули атаки
    import utils
    import dcp
    import zvp_glv_inter_easy_prec as inter_easy
    print("🔧 Модули атаки импортированы успешно")
    
except ImportError as e:
    print(f"❌ Ошибка импорта: {e}")
    if "sage" in str(e).lower():
        print("📝 Для работы скрипта требуется SageMath:")
        print("   Ubuntu/Debian: sudo apt-get install sagemath")
        print("   Conda: conda install -c conda-forge sage")
        print("   Или запустите через: sage -python generate_dcp_points.py")
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


def setup_zvp_parameters(pubkey_hex, verbose=True):
    """Настройка параметров ZVP для генерации DCP точек"""
    if verbose:
        print(f"🔧 Настройка параметров ZVP...")
        print(f"   Публичный ключ: {pubkey_hex}")
    
    # Парсим публичный ключ
    try:
        pub_x, pub_y = parse_hex_pubkey(pubkey_hex)
        if verbose:
            print(f"   Координата X: {hex(pub_x)}")
            print(f"   Координата Y: {hex(pub_y)}")
    except ValueError as e:
        print(f"❌ Ошибка парсинга публичного ключа: {e}")
        return None
    
    # Создаем параметры ZVP
    zvp_params = utils.ZVPparams(256)  # Используем 256-битную кривую
    
    # Устанавливаем secp256k1
    if verbose:
        print("🔐 Настройка криптографических параметров...")
    zvp_params.generate_secp256k1_secrets()
    if verbose:
        print(f"   Кривая: secp256k1")
        print(f"   Порядок поля: {hex(zvp_params.glv.p)}")
        print(f"   Порядок группы: {hex(zvp_params.glv.order)}")
    
    # Проверяем, что публичный ключ лежит на кривой
    try:
        point = zvp_params.glv.curve(pub_x, pub_y)
        if verbose:
            print(f"✅ Публичный ключ валиден и лежит на кривой")
    except Exception as e:
        print(f"❌ Публичный ключ не лежит на кривой secp256k1: {e}")
        return None
    
    return zvp_params, point


def setup_registers_for_polynomial(polynomial_index, verbose=True):
    """Настройка регистров для конкретного полинома"""
    registers = utils.Registers()
    
    # Получаем secp256k1 полиномы
    secp256k1_polynomials = utils.get_secp256k1_polynomials(extended=True)
    
    # Преобразуем словарь в список для индексации
    polynomial_list = list(secp256k1_polynomials.values())
    polynomial_keys = list(secp256k1_polynomials.keys())
    
    if polynomial_index >= len(polynomial_list):
        raise ValueError(f"Индекс полинома {polynomial_index} вне диапазона (доступно: 0-{len(polynomial_list)-1})")
    
    # Добавляем выбранный полином
    f, g = polynomial_list[polynomial_index]
    registers.add_tuple(f, g)
    
    if verbose:
        polynomial_name = polynomial_keys[polynomial_index]
        print(f"📊 Добавлен полином #{polynomial_index} ({polynomial_name}): {registers.to_strings()[0]}")
    
    return registers


def generate_dcp_experiments(zvp_params, w, polynomial_index, num_experiments=1000, verbose=True):
    """Генерация DCP экспериментов для заданного окна w"""
    if verbose:
        print(f"\n🧪 Генерация DCP экспериментов...")
        print(f"   Размер окна w: {w}")
        print(f"   Полином: #{polynomial_index}")
        print(f"   Количество экспериментов: {num_experiments}")
    
    # Настраиваем регистры для полинома
    zvp_params.registers = setup_registers_for_polynomial(polynomial_index, verbose)
    
    # Устанавливаем атаку
    zvp_params.attack = dcp.interleaving_dcp_experiment
    
    # Получаем все возможные w-NAF значения для данного окна
    wnaf_values = inter_easy.all_rwnaf_values(w)
    if verbose:
        print(f"   w-NAF значения: {wnaf_values}")
    
    results_list = []
    total_combinations = len(wnaf_values) * len(wnaf_values)
    
    if verbose:
        print(f"   Общее количество комбинаций: {total_combinations}")
        print(f"   Запуск экспериментов...")
    
    processed = 0
    successful = 0
    
    for w0 in wnaf_values:
        for w1 in wnaf_values:
            # Устанавливаем секретные ключи для эксперимента
            zvp_params.secrets.k = -1  # Placeholder
            zvp_params.secrets.k0, zvp_params.secrets.k1 = w0, w1
            
            try:
                # Выполняем DCP эксперимент
                zvp_params.do_attack()
                result_dict = zvp_params.results_to_dict()
                results_list.append(result_dict)
                
                if result_dict["result"]["recovered"]:
                    successful += 1
                    
            except Exception as e:
                if verbose:
                    print(f"   ⚠️  Ошибка в эксперименте ({w0}, {w1}): {e}")
                # Добавляем неудачный результат
                result_dict = {
                    "k0": int(w0), "k1": int(w1), "k": -1,
                    "result": {"recovered": 0, "point": [], "time_zvp": 0.0, "nguesses": 0}
                }
                results_list.append(result_dict)
            
            processed += 1
            
            # Показываем прогресс каждые 10%
            if verbose and processed % max(1, total_combinations // 10) == 0:
                progress = (processed / total_combinations) * 100
                print(f"   Прогресс: {progress:.1f}% ({processed}/{total_combinations}), найдено точек: {successful}")
                
            # Ограничиваем количество экспериментов если задано
            if len(results_list) >= num_experiments:
                break
        
        if len(results_list) >= num_experiments:
            break
    
    if verbose:
        print(f"✅ Завершено экспериментов: {len(results_list)}")
        print(f"   Успешных (найдены точки): {successful}")
        print(f"   Процент успеха: {(successful/len(results_list)*100):.1f}%")
    
    return results_list


def save_dcp_results(results_list, w, polynomial_index, timestamp=None):
    """Сохранение результатов DCP экспериментов"""
    if not os.path.exists("attack/results"):
        os.makedirs("attack/results")
    
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
    
    # Формируем имя файла согласно формату проекта
    filename = f"attack/results/interleaving_dcp_experiment_256_{timestamp}.json"
    
    print(f"💾 Сохранение результатов в {filename}...")
    
    # Подготавливаем метаданные
    metadata = {
        "timestamp": datetime.now().isoformat(),
        "experiment_type": "interleaving_dcp_experiment",
        "window_size": w,
        "polynomial_index": polynomial_index,
        "curve": "secp256k1",
        "total_experiments": len(results_list),
        "successful_experiments": sum(1 for r in results_list if r["result"]["recovered"])
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


def generate_remapped_points(zvp_params, w, dcp_results_file, verbose=True):
    """Генерация remapped точек из DCP результатов"""
    if verbose:
        print(f"\n🔄 Генерация remapped точек для w={w}...")
    
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
    all_points = set()
    for result in results:
        if result["result"]["point"]:
            point = zvp_params.glv.curve(*result["result"]["point"])
            all_points.add(point)
    
    if verbose:
        print(f"   Уникальных точек найдено: {len(all_points)}")
    
    if len(all_points) == 0:
        print("❌ Не найдено точек для remapping")
        return None
    
    # Remapping точек
    all_pos_scalars = inter_easy.all_rwnaf_values(w)
    point_list = []
    
    if verbose:
        print(f"   Выполняется remapping для w-NAF значений: {all_pos_scalars}")
    
    for i, point in enumerate(all_points):
        scalars = []
        for w0 in all_pos_scalars:
            for w1 in all_pos_scalars:
                P, Q = w0 * point, w1 * zvp_params.glv.lam * point
                if zvp_params.registers.is_zero(P, Q):
                    scalars.append((int(w0), int(w1)))
        
        point_list.append([(int(point[0]), int(point[1])), scalars])
        
        if verbose and (i + 1) % 10 == 0:
            print(f"   Обработано точек: {i + 1}/{len(all_points)}")
    
    # Формируем данные для сохранения
    to_save = {
        "register": zvp_params.registers.to_strings(), 
        "points": point_list
    }
    
    if verbose:
        print(f"✅ Remapping завершен: {len(point_list)} точек")
    
    return to_save


def save_remapped_points(remapped_data, w):
    """Сохранение remapped точек в формате проекта"""
    filename = f"attack/results/interleaving_secp256k1_remapped_{w}.json"
    
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
            json.dump(existing_data, f)
        print(f"✅ Remapped точки сохранены: {len(remapped_data['points'])} точек")
        return filename
    except Exception as e:
        print(f"❌ Ошибка сохранения remapped точек: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Генератор предвычисленных DCP точек для ZVP-GLV атаки",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  # Быстрая генерация для w=4
  sage -python generate_dcp_points.py --pubkey YOUR_KEY --w 4 --experiments 100
  
  # Полная генерация всех точек для w=3,4,5  
  sage -python generate_dcp_points.py --pubkey YOUR_KEY --w 3 4 5 --full
  
  # Генерация только для конкретного полинома
  sage -python generate_dcp_points.py --pubkey YOUR_KEY --w 4 --polynomial 0

Этот скрипт создает файлы:
  - attack/results/interleaving_dcp_experiment_256_TIMESTAMP.json (DCP эксперименты)
  - attack/results/interleaving_secp256k1_remapped_W.json (remapped точки)
  
Созданные файлы используются attack_zvp_glv_inter_easy_prec.py на "Этап 1".
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
        help='Индекс полинома secp256k1 (0-12, по умолчанию: 0)'
    )
    
    parser.add_argument(
        '--experiments',
        type=int,
        default=1000,
        help='Максимальное количество DCP экспериментов (по умолчанию: 1000, -1 для всех)'
    )
    
    parser.add_argument(
        '--full',
        action='store_true',
        help='Полная генерация всех возможных экспериментов (игнорирует --experiments)'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Тихий режим (минимум вывода)'
    )
    
    parser.add_argument(
        '--skip-dcp',
        action='store_true',
        help='Пропустить генерацию DCP экспериментов, только remapping'
    )
    
    parser.add_argument(
        '--dcp-file',
        help='Использовать существующий файл DCP результатов для remapping'
    )
    
    args = parser.parse_args()
    
    verbose = not args.quiet
    
    if verbose:
        print("🎯 Генератор предвычисленных DCP точек")
        print("=" * 50)
    
    # Настройка параметров
    result = setup_zvp_parameters(args.pubkey, verbose)
    if result is None:
        sys.exit(1)
    
    zvp_params, pubkey_point = result
    
    # Обрабатываем каждый размер окна
    for w in args.w:
        if verbose:
            print(f"\n🚀 Обработка размера окна w={w}")
        
        dcp_file = None
        
        # Генерация DCP экспериментов (если не пропускается)
        if not args.skip_dcp:
            if verbose:
                print(f"📊 Этап 1: Генерация DCP экспериментов")
            
            experiments_count = -1 if args.full else args.experiments
            
            start_time = time.time()
            results = generate_dcp_experiments(
                zvp_params, w, args.polynomial, 
                experiments_count, verbose
            )
            duration = time.time() - start_time
            
            if verbose:
                print(f"   Время генерации: {duration:.1f} секунд")
            
            # Сохраняем DCP результаты
            dcp_file = save_dcp_results(results, w, args.polynomial)
            if not dcp_file:
                print(f"❌ Не удалось сохранить DCP результаты для w={w}")
                continue
        else:
            dcp_file = args.dcp_file
            if not dcp_file:
                print(f"❌ Требуется --dcp-file при использовании --skip-dcp")
                continue
        
        # Генерация remapped точек
        if verbose:
            print(f"🔄 Этап 2: Генерация remapped точек")
        
        start_time = time.time()
        remapped_data = generate_remapped_points(zvp_params, w, dcp_file, verbose)
        duration = time.time() - start_time
        
        if not remapped_data:
            print(f"❌ Не удалось создать remapped точки для w={w}")
            continue
            
        if verbose:
            print(f"   Время remapping: {duration:.1f} секунд")
        
        # Сохраняем remapped точки
        remapped_file = save_remapped_points(remapped_data, w)
        if not remapped_file:
            print(f"❌ Не удалось сохранить remapped точки для w={w}")
            continue
        
        if verbose:
            print(f"✅ Завершено для w={w}")
            print(f"   DCP файл: {dcp_file}")
            print(f"   Remapped файл: {remapped_file}")
    
    if verbose:
        print(f"\n🎉 Генерация предвычисленных точек завершена!")
        print(f"💡 Теперь можно запускать:")
        for w in args.w:
            print(f"   python attack_zvp_glv_inter_easy_prec.py --pubkey {args.pubkey} --w {w}")


if __name__ == "__main__":
    main()