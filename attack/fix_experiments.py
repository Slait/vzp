#!/usr/bin/env sage

"""
Исправленная версия experiments.py
Решает проблемы:
1. Переполнение стека PARI
2. Ошибки сериализации JSON для объектов Sage
"""

from sage.all import ZZ, log, sqrt
import zvp_glv_sac
import zvp_glv_inter_easy_prec as inter_easy
import zvp_ltr_signed
from datetime import datetime
import json, os
import numpy
import dcp
import utils
from utils import ZVPparams
from copy import deepcopy

FLOAT_FORMAT = "{0:0.2f}"


def safe_json_convert(obj):
    """
    Безопасно конвертирует объекты Sage в JSON-совместимые типы
    """
    if hasattr(obj, 'sage'):
        # Объект Sage
        if hasattr(obj, '__int__'):
            return int(obj)
        elif hasattr(obj, '__float__'):
            return float(obj)
        elif hasattr(obj, '__str__'):
            return str(obj)
    elif isinstance(obj, dict):
        return {key: safe_json_convert(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [safe_json_convert(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        # Объект с атрибутами
        return safe_json_convert(obj.__dict__)
    else:
        # Уже JSON-совместимый тип
        return obj


def save_results(results, filename):
    """Сохраняет результаты с безопасной JSON сериализацией"""
    if not os.path.exists("results"):
        os.makedirs("results")
    time = datetime.today().strftime("%Y-%m-%d_%H:%M:%S")
    filename = os.path.join("results", f"{filename}_{time}.json")
    
    # Безопасная конвертация в JSON-совместимые типы
    safe_results = safe_json_convert(results)
    
    try:
        with open(filename, "w") as f:
            json.dump(safe_results, f, indent=2)
        print(f"✓ Результаты сохранены в: {filename}")
    except Exception as e:
        print(f"❌ Ошибка сохранения: {e}")
        # Попытка сохранить как текст
        try:
            with open(filename.replace('.json', '.txt'), "w") as f:
                f.write(str(safe_results))
            print(f"✓ Результаты сохранены как текст: {filename.replace('.json', '.txt')}")
        except:
            print("❌ Не удалось сохранить результаты")


def setup_pari_stack():
    """Настройка размера стека PARI"""
    try:
        import pari
        # Увеличиваем размер стека до 32GB если возможно
        pari.allocatemem(32 * 1024 * 1024 * 1024)  # 32GB
        print("✓ Размер стека PARI увеличен до 32GB")
    except:
        try:
            import pari
            # Если 32GB не работает, попробуем 8GB
            pari.allocatemem(8 * 1024 * 1024 * 1024)  # 8GB
            print("✓ Размер стека PARI установлен на 8GB")
        except:
            print("⚠️  Не удалось изменить размер стека PARI. Используется размер по умолчанию.")


def safe_attack_wrapper(zvpparams):
    """Безопасный wrapper для выполнения атак с обработкой ошибок стека"""
    try:
        setup_pari_stack()
        zvpparams.do_attack()
        return zvpparams.results_to_dict()
    except Exception as e:
        error_msg = str(e)
        if "PARI stack overflows" in error_msg:
            print("❌ Переполнение стека PARI! Попробуйте:")
            print("1. Уменьшить target_bits")
            print("2. Увеличить размер стека PARI в ~/.gprc")
            print("3. Использовать меньше экспериментов")
        else:
            print(f"❌ Ошибка атаки: {e}")
        
        # Возвращаем безопасный результат с ошибкой
        return {
            "error": error_msg,
            "target_bits": int(zvpparams.target_bits) if zvpparams.target_bits else 0,
            "attack": str(zvpparams.attack.__name__) if zvpparams.attack else "unknown"
        }


def dcp_all_secp256k1_interleaving_experiments(zvpparams, w):
    """DCP эксперименты для interleaving с защитой от переполнения стека"""
    print(f"🚀 Запуск DCP interleaving экспериментов (w={w})")
    setup_pari_stack()
    
    secrets = zvpparams.secrets
    zvpparams.attack = dcp.interleaving_dcp_experiment
    results_list = []
    zvpparams.glv.set_secp256k1()
    wnaf_values = inter_easy.all_rwnaf_values(w)
    
    total_combinations = len(wnaf_values) ** 2
    print(f"Общее количество комбинаций: {total_combinations}")
    
    if total_combinations > 100:
        print("⚠️  Большое количество комбинаций! Это может занять много времени.")
        response = input("Продолжить? (y/n): ")
        if response.lower() not in ['y', 'yes', 'да']:
            return
    
    count = 0
    for w0 in wnaf_values:
        for w1 in wnaf_values:
            count += 1
            print(f"Прогресс: {count}/{total_combinations} ({100*count/total_combinations:.1f}%)")
            
            secrets.k = -1
            secrets.k0, secrets.k1 = w0, w1
            result = safe_attack_wrapper(zvpparams)
            results_list.append(result)
    
    save_results(results_list, f"{zvpparams.filename}_{w}")


def dcp_all_secp256k1_experiments(zvpparams):
    """DCP эксперименты для всех k с защитой от переполнения стека"""
    print("🚀 Запуск стандартных DCP экспериментов")
    setup_pari_stack()
    
    secrets = zvpparams.secrets
    zvpparams.attack = dcp.glv_dcp_experiment
    results_list = []
    lower_bound = 2 ** (zvpparams.target_bits - 1)
    upper_bound = 2 ** (zvpparams.target_bits)
    zvpparams.glv.set_secp256k1()
    
    total_experiments = upper_bound - lower_bound
    print(f"Количество экспериментов: {total_experiments}")
    
    if total_experiments > 50:
        print("⚠️  Большое количество экспериментов! Это может занять много времени.")
        response = input("Продолжить? (y/n): ")
        if response.lower() not in ['y', 'yes', 'да']:
            return
    
    for i, k in enumerate(range(lower_bound, upper_bound)):
        print(f"Эксперимент {i+1}/{total_experiments}: k={k}")
        secrets.k = k
        secrets.k0, secrets.k1 = -1, -1
        result = safe_attack_wrapper(zvpparams)
        results_list.append(result)
    
    save_results(results_list, zvpparams.filename)


def glvdcp_all_secp256k1_experiments(zvpparams):
    """GLV DCP эксперименты для всех k0, k1 с защитой от переполнения стека"""
    print("🚀 Запуск полных GLV DCP экспериментов")
    setup_pari_stack()
    
    secrets = zvpparams.secrets
    zvpparams.attack = dcp.glv_dcp_experiment
    results_list = []
    lower_bound = 2 ** (zvpparams.target_bits - 1)
    upper_bound = 2 ** (zvpparams.target_bits)
    zvpparams.glv.set_secp256k1()
    
    total_experiments = (upper_bound - lower_bound) ** 2
    print(f"Общее количество экспериментов: {total_experiments}")
    
    if total_experiments > 100:
        print("⚠️  Очень большое количество экспериментов! Рекомендуется уменьшить target_bits.")
        response = input("Продолжить? (y/n): ")
        if response.lower() not in ['y', 'yes', 'да']:
            return
    
    count = 0
    for k0 in range(lower_bound, upper_bound):
        for k1 in range(lower_bound, upper_bound):
            count += 1
            print(f"Прогресс: {count}/{total_experiments} ({100*count/total_experiments:.1f}%)")
            
            secrets.k = -1
            secrets.k0, secrets.k1 = k0, k1
            result = safe_attack_wrapper(zvpparams)
            results_list.append(result)
    
    save_results(results_list, zvpparams.filename)


def zvp_attack_experiments(zvpparams, n_exp, t_bounds):
    """ZVP эксперименты с защитой от переполнения стека"""
    print(f"🚀 Запуск ZVP экспериментов (n_exp={n_exp}, t_bounds={t_bounds})")
    setup_pari_stack()
    
    for zvp_target in map(ZZ, range(*t_bounds)):
        print(f"\nЦелевые биты: {zvp_target}")
        results_list = []
        zvpparams.target_bits = zvp_target
        
        for i in range(n_exp):
            if zvpparams.verbose:
                print(f"Эксперимент {i + 1}/{n_exp}")
            
            try:
                zvpparams.generate_secrets()
                result = safe_attack_wrapper(zvpparams)
                results_list.append(result)
            except Exception as e:
                print(f"❌ Ошибка в эксперименте {i+1}: {e}")
                results_list.append({"error": str(e), "experiment": i+1})
        
        save_results(results_list, zvpparams.filename)


def zvp_attack_experiments_secp256k1(zvpparams, n_exp, t_bounds):
    """ZVP эксперименты для secp256k1 с защитой от переполнения стека"""
    print(f"🚀 Запуск ZVP экспериментов для secp256k1 (n_exp={n_exp}, t_bounds={t_bounds})")
    setup_pari_stack()
    
    for zvp_target in map(ZZ, range(*t_bounds)):
        print(f"\nЦелевые биты: {zvp_target}")
        results_list = []
        zvpparams.target_bits = zvp_target
        
        for i in range(n_exp):
            if zvpparams.verbose:
                print(f"Эксперимент {i + 1}/{n_exp}")
            
            try:
                zvpparams.generate_secp256k1_secrets()
                result = safe_attack_wrapper(zvpparams)
                results_list.append(result)
            except Exception as e:
                print(f"❌ Ошибка в эксперименте {i+1}: {e}")
                results_list.append({"error": str(e), "experiment": i+1})
        
        save_results(results_list, zvpparams.filename)


def DCP_main():
    """Главная функция DCP с улучшенной обработкой ошибок"""
    print("=" * 60)
    print("        DCP АТАКА (исправленная версия)")
    print("=" * 60)
    
    # Настройка
    zvpparams = ZVPparams(bits=256)
    zvpparams.attack = dcp.glv_dcp_experiment
    zvpparams.target_bits = 4  # Начинаем с малого значения
    
    # Добавление полиномов secp256k1
    secp256k1_polynomials = utils.get_secp256k1_polynomials()
    selection = ["f1", "f11", "f6", "f7", "f9"]
    for name in selection:
        zvpparams.registers.add_tuple(*secp256k1_polynomials[name])
    
    print(f"✓ Настроена атака: {zvpparams.attack.__name__}")
    print(f"✓ Целевые биты: {zvpparams.target_bits}")
    print(f"✓ Полиномы: {', '.join(selection)}")
    
    # Запуск эксперимента
    try:
        zvp_attack_experiments_secp256k1(zvpparams, n_exp=1, t_bounds=(4, 5))
        print("\n✅ DCP атака завершена успешно!")
    except Exception as e:
        print(f"\n❌ Ошибка выполнения DCP атаки: {e}")


def interleaving_main():
    """Главная функция interleaving атаки"""
    print("=" * 60)
    print("    INTERLEAVING АТАКА (исправленная версия)")
    print("=" * 60)
    
    zvpparams = ZVPparams(bits=256)
    zvpparams.attack = inter_easy.zvp_glv_interleaving_easy_regular_3
    zvpparams.registers = utils.load_efd_secp256k1_registers()["modified:mmadd-2009-bl"]
    
    print(f"✓ Настроена атака: {zvpparams.attack.__name__}")
    print("✓ Регистры: modified:mmadd-2009-bl")
    
    try:
        zvp_attack_experiments_secp256k1(zvpparams, n_exp=1, t_bounds=(0, 1))
        print("\n✅ Interleaving атака завершена успешно!")
    except Exception as e:
        print(f"\n❌ Ошибка выполнения interleaving атаки: {e}")


def ZVP_main():
    """Главная функция ZVP атаки"""
    print("=" * 60)
    print("      ZVP АТАКА (исправленная версия)")
    print("=" * 60)
    
    zvpparams = ZVPparams(bits=256)
    zvpparams.attack = inter_easy.zvp_glv_interleaving_easy_regular_4
    
    secp256k1_polynomials = utils.get_secp256k1_polynomials()
    selection = ["f1", "f11", "f6", "f7", "f9"]
    for name in selection:
        zvpparams.registers.add_tuple(*secp256k1_polynomials[name])
    
    print(f"✓ Настроена атака: {zvpparams.attack.__name__}")
    print(f"✓ Полиномы: {', '.join(selection)}")
    
    try:
        zvp_attack_experiments_secp256k1(zvpparams, n_exp=1, t_bounds=(0, 1))
        print("\n✅ ZVP атака завершена успешно!")
    except Exception as e:
        print(f"\n❌ Ошибка выполнения ZVP атаки: {e}")


if __name__ == "__main__":
    print("Выберите атаку:")
    print("1. DCP атака")
    print("2. Interleaving атака") 
    print("3. ZVP атака")
    
    try:
        choice = input("Введите номер (1-3): ").strip()
        
        if choice == "1":
            DCP_main()
        elif choice == "2":
            interleaving_main()
        elif choice == "3":
            ZVP_main()
        else:
            print("❌ Неверный выбор. Запускаю DCP атаку по умолчанию.")
            DCP_main()
            
    except KeyboardInterrupt:
        print("\n\n❌ Выполнение прервано пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")