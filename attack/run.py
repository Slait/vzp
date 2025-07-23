#!/usr/bin/env sage

"""
Интерактивный запуск ZVP-GLV атак
Позволяет выбрать тип атаки и настроить параметры
"""

from sage.all import ZZ
import utils
import dcp
import zvp_glv_inter_easy_prec as inter_easy
import zvp_ltr_signed
import glv
import experiments
import sys
import os

def print_banner():
    """Печатает заголовок программы"""
    print("=" * 70)
    print("      ZVP-GLV АТАКИ НА ЭЛЛИПТИЧЕСКИЕ КРИВЫЕ")
    print("    Zero-Value Point attacks with GLV decomposition")
    print("=" * 70)
    print()

def print_attack_info():
    """Печатает информацию о типах атак"""
    print("ДОСТУПНЫЕ ТИПЫ АТАК:")
    print()
    print("1. DCP АТАКИ (Dependent Coordinates Problem)")
    print("   - Решают проблему зависимых координат")
    print("   - Восстанавливают части приватного ключа")
    print("   - Подтипы:")
    print("     a) GLV DCP эксперименты")
    print("     b) Полные GLV DCP эксперименты") 
    print("     c) DCP Interleaving эксперименты")
    print()
    print("2. ZVP-GLV INTERLEAVING АТАКИ")
    print("   - Атаки на interleaving алгоритм multiscalar multiplication")
    print("   - Поддерживают различные размеры окон (w=3,4,5)")
    print("   - Используют предвычисленные DCP точки")
    print()
    print("3. КЛАССИЧЕСКИЕ ZVP АТАКИ")
    print("   - Атаки на signed left-to-right алгоритм")
    print("   - Базовый ZVP подход без GLV оптимизаций")
    print()

def get_user_input(prompt, default_value, input_type=str):
    """Получает пользовательский ввод с значением по умолчанию"""
    try:
        user_input = input(f"{prompt} [по умолчанию: {default_value}]: ").strip()
        if not user_input:
            return default_value
        
        if input_type == int:
            return int(user_input)
        elif input_type == float:
            return float(user_input)
        elif input_type == bool:
            return user_input.lower() in ['y', 'yes', 'да', 'true', '1']
        else:
            return user_input
    except (ValueError, KeyboardInterrupt):
        print(f"Используется значение по умолчанию: {default_value}")
        return default_value

def setup_custom_key(zvpparams):
    """Настройка пользовательского ключа"""
    print("\n" + "="*50)
    print("НАСТРОЙКА ПРИВАТНОГО КЛЮЧА")
    print("="*50)
    
    use_custom = get_user_input(
        "Использовать собственный приватный ключ? (y/n)", 
        "n", 
        bool
    )
    
    if use_custom:
        print("\nВведите приватный ключ в одном из форматов:")
        print("- Шестнадцатеричный: 0x1234567890abcdef...")
        print("- Десятичный: 123456789...")
        
        key_input = get_user_input(
            "Приватный ключ", 
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        
        try:
            if key_input.startswith('0x') or key_input.startswith('0X'):
                private_key = int(key_input, 16)
            else:
                private_key = int(key_input)
            
            # Установка ключа
            zvpparams.secrets.k = ZZ(private_key)
            
            # GLV декомпозиция
            decomp = glv.glv_decompose_simple(
                private_key, 
                zvpparams.glv.lam, 
                zvpparams.glv.order
            )
            zvpparams.secrets.k0 = decomp[0]
            zvpparams.secrets.k1 = decomp[1]
            
            print(f"\n✓ Установлен ключ: {hex(private_key)}")
            print(f"✓ GLV декомпозиция: k0={zvpparams.secrets.k0}, k1={zvpparams.secrets.k1}")
            
        except ValueError:
            print("❌ Ошибка в формате ключа. Используется случайный ключ.")
            zvpparams.generate_secp256k1_secrets()
    else:
        print("✓ Используется случайно сгенерированный ключ")
        zvpparams.generate_secp256k1_secrets()

def configure_dcp_attack():
    """Настройка параметров DCP атаки"""
    print("\n" + "="*50)
    print("НАСТРОЙКА DCP АТАКИ")
    print("="*50)
    
    print("\nВыберите тип DCP атаки:")
    print("1. GLV DCP эксперименты (zvp_attack_experiments_secp256k1)")
    print("   - Стандартные GLV DCP атаки")
    print("   - Настраиваемое количество экспериментов и целевых бит")
    print()
    print("2. Полные GLV DCP эксперименты (glvdcp_all_secp256k1_experiments)")
    print("   - Полный перебор всех комбинаций k0, k1")
    print("   - Более медленно, но полнее")
    print()
    print("3. DCP Interleaving эксперименты (dcp_all_secp256k1_interleaving_experiments)")
    print("   - DCP атаки на interleaving алгоритм")
    print("   - Поддержка различных размеров окон")
    
    dcp_type = get_user_input("Выберите тип (1-3)", "1", int)
    
    if dcp_type == 1:
        print("\n--- Параметры GLV DCP экспериментов ---")
        n_exp = get_user_input(
            "Количество экспериментов (n_exp)", 
            1, int
        )
        t_bounds_start = get_user_input(
            "Начальное количество целевых бит", 
            4, int
        )
        t_bounds_end = get_user_input(
            "Конечное количество целевых бит", 
            5, int
        )
        return ('glv_dcp', {'n_exp': n_exp, 't_bounds': (t_bounds_start, t_bounds_end)})
    
    elif dcp_type == 2:
        print("\n--- Параметры полных GLV DCP экспериментов ---")
        target_bits = get_user_input(
            "Количество целевых бит (target_bits)", 
            4, int
        )
        return ('full_glv_dcp', {'target_bits': target_bits})
    
    elif dcp_type == 3:
        print("\n--- Параметры DCP Interleaving экспериментов ---")
        window_size = get_user_input(
            "Размер окна (w)", 
            4, int
        )
        return ('dcp_interleaving', {'window_size': window_size})
    
    else:
        print("❌ Неверный выбор. Используется тип 1.")
        return ('glv_dcp', {'n_exp': 1, 't_bounds': (4, 5)})

def configure_interleaving_attack():
    """Настройка параметров Interleaving атаки"""
    print("\n" + "="*50)
    print("НАСТРОЙКА ZVP-GLV INTERLEAVING АТАКИ")
    print("="*50)
    
    print("\nВыберите размер окна для interleaving атаки:")
    print("w=3: zvp_glv_interleaving_easy_regular_3")
    print("w=4: zvp_glv_interleaving_easy_regular_4") 
    print("w=5: zvp_glv_interleaving_easy_regular_5")
    print()
    print("Размер окна влияет на:")
    print("- Количество предвычисленных точек")
    print("- Сложность атаки")
    print("- Время выполнения")
    
    window_size = get_user_input("Размер окна (3-5)", 4, int)
    
    if window_size not in [3, 4, 5]:
        print("❌ Неверный размер окна. Используется w=4.")
        window_size = 4
    
    print("\n--- Параметры эксперимента ---")
    n_exp = get_user_input("Количество экспериментов (n_exp)", 1, int)
    t_bounds_start = get_user_input("Начальные целевые биты", 0, int)
    t_bounds_end = get_user_input("Конечные целевые биты", 1, int)
    
    return {
        'window_size': window_size,
        'n_exp': n_exp,
        't_bounds': (t_bounds_start, t_bounds_end)
    }

def configure_zvp_attack():
    """Настройка параметров классической ZVP атаки"""
    print("\n" + "="*50)
    print("НАСТРОЙКА КЛАССИЧЕСКОЙ ZVP АТАКИ")
    print("="*50)
    
    print("Классическая ZVP атака на signed left-to-right алгоритм")
    print("- Не использует GLV оптимизации")
    print("- Работает с обычными скалярами")
    print("- Базовый подход ZVP")
    
    print("\n--- Параметры эксперимента ---")
    n_exp = get_user_input("Количество экспериментов (n_exp)", 1, int)
    t_bounds_start = get_user_input("Начальные целевые биты", 4, int)
    t_bounds_end = get_user_input("Конечные целевые биты", 5, int)
    
    return {
        'n_exp': n_exp,
        't_bounds': (t_bounds_start, t_bounds_end)
    }

def setup_polynomials(zvpparams, attack_type):
    """Настройка полиномов для атаки"""
    print("\n--- Настройка полиномов ---")
    
    if attack_type == 'interleaving':
        # Для interleaving используем предустановленные регистры
        zvpparams.registers = utils.load_efd_secp256k1_registers()["modified:mmadd-2009-bl"]
        print("✓ Используются регистры EFD: modified:mmadd-2009-bl")
    else:
        # Для DCP атак используем выбранные полиномы
        secp256k1_polynomials = utils.get_secp256k1_polynomials()
        selection = ["f1", "f11", "f6", "f7", "f9"]
        
        print("Доступные полиномы secp256k1:")
        for i, name in enumerate(selection, 1):
            print(f"{i}. {name}")
        
        use_default = get_user_input(
            "Использовать стандартный набор полиномов? (y/n)", 
            "y", bool
        )
        
        if use_default:
            for name in selection:
                zvpparams.registers.add_tuple(*secp256k1_polynomials[name])
            print(f"✓ Добавлены полиномы: {', '.join(selection)}")
        else:
            print("Введите номера полиномов через пробел (например: 1 2 3):")
            selected = get_user_input("Полиномы", "1 2 3 4 5")
            try:
                indices = [int(x) - 1 for x in selected.split()]
                selected_names = [selection[i] for i in indices if 0 <= i < len(selection)]
                for name in selected_names:
                    zvpparams.registers.add_tuple(*secp256k1_polynomials[name])
                print(f"✓ Добавлены полиномы: {', '.join(selected_names)}")
            except:
                # Fallback к стандартному набору
                for name in selection:
                    zvpparams.registers.add_tuple(*secp256k1_polynomials[name])
                print("❌ Ошибка выбора. Используется стандартный набор.")

def run_dcp_attack(zvpparams, attack_config):
    """Запуск DCP атаки"""
    attack_type, params = attack_config
    
    print(f"\n🚀 Запуск DCP атаки: {attack_type}")
    print("Параметры:", params)
    
    if attack_type == 'glv_dcp':
        print("Выполняется: zvp_attack_experiments_secp256k1")
        experiments.zvp_attack_experiments_secp256k1(
            zvpparams, 
            n_exp=params['n_exp'], 
            t_bounds=params['t_bounds']
        )
    
    elif attack_type == 'full_glv_dcp':
        print("Выполняется: glvdcp_all_secp256k1_experiments")
        zvpparams.target_bits = params['target_bits']
        experiments.glvdcp_all_secp256k1_experiments(zvpparams)
    
    elif attack_type == 'dcp_interleaving':
        print("Выполняется: dcp_all_secp256k1_interleaving_experiments")
        experiments.dcp_all_secp256k1_interleaving_experiments(
            zvpparams, 
            params['window_size']
        )

def run_interleaving_attack(zvpparams, config):
    """Запуск Interleaving атаки"""
    window_size = config['window_size']
    
    print(f"\n🚀 Запуск ZVP-GLV Interleaving атаки (w={window_size})")
    
    # Выбор функции атаки в зависимости от размера окна
    attack_functions = {
        3: inter_easy.zvp_glv_interleaving_easy_regular_3,
        4: inter_easy.zvp_glv_interleaving_easy_regular_4,
        5: inter_easy.zvp_glv_interleaving_easy_regular_5
    }
    
    zvpparams.attack = attack_functions[window_size]
    
    print("Выполняется: zvp_attack_experiments_secp256k1")
    experiments.zvp_attack_experiments_secp256k1(
        zvpparams, 
        n_exp=config['n_exp'], 
        t_bounds=config['t_bounds']
    )

def run_zvp_attack(zvpparams, config):
    """Запуск классической ZVP атаки"""
    print("\n🚀 Запуск классической ZVP атаки")
    
    # Настройка атаки
    zvpparams.attack = zvp_ltr_signed.zvp_attack_signed_ltr
    
    print("Выполняется: zvp_attack_experiments")
    experiments.zvp_attack_experiments(
        zvpparams, 
        n_exp=config['n_exp'], 
        t_bounds=config['t_bounds']
    )

def main():
    """Главная функция"""
    try:
        print_banner()
        print_attack_info()
        
        # Выбор типа атаки
        print("ВЫБОР ТИПА АТАКИ:")
        print("1. DCP Атаки")
        print("2. ZVP-GLV Interleaving Атаки") 
        print("3. Классические ZVP Атаки")
        
        attack_choice = get_user_input("Выберите тип атаки (1-3)", "1", int)
        
        # Создание параметров атаки
        zvpparams = utils.ZVPparams(bits=256)
        zvpparams.glv.set_secp256k1()
        zvpparams.verbose = True
        
        # Настройка ключа
        setup_custom_key(zvpparams)
        
        # Настройка и запуск выбранной атаки
        if attack_choice == 1:
            attack_config = configure_dcp_attack()
            setup_polynomials(zvpparams, 'dcp')
            run_dcp_attack(zvpparams, attack_config)
            
        elif attack_choice == 2:
            config = configure_interleaving_attack()
            setup_polynomials(zvpparams, 'interleaving')
            run_interleaving_attack(zvpparams, config)
            
        elif attack_choice == 3:
            config = configure_zvp_attack()
            setup_polynomials(zvpparams, 'zvp')
            run_zvp_attack(zvpparams, config)
            
        else:
            print("❌ Неверный выбор атаки.")
            return
        
        print("\n" + "="*70)
        print("✅ АТАКА ЗАВЕРШЕНА")
        print("="*70)
        print(f"Результаты сохранены в папке: results/")
        print("Используйте results_visual.py для анализа результатов")
        
    except KeyboardInterrupt:
        print("\n\n❌ Выполнение прервано пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка выполнения: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()