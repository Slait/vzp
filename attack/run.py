#!/usr/bin/env sage

"""
Интерактивный запуск ZVP-GLV атак
Позволяет выбрать тип атаки и настроить параметры
"""

from sage.all import ZZ, EllipticCurve, GF
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

def setup_curve_selection(zvpparams):
    """Настройка выбора эллиптической кривой"""
    print("\n" + "="*50)
    print("ВЫБОР ЭЛЛИПТИЧЕСКОЙ КРИВОЙ")
    print("="*50)
    
    print("\nДоступные кривые:")
    print("1. secp256k1 (Bitcoin) - y² = x³ + 7 (mod p256)")
    print("   p = 2²⁵⁶ - 2³² - 977")
    print("   Стандартная GLV кривая с быстрым эндоморфизмом")
    print()
    print("2. Тестовая кривая p=79 - y² = x³ + 7 (mod 67)")
    print("   Малая кривая для тестирования алгоритмов")
    print("   Базовая точка: (2, 22)")
    print()
    print("3. Пользовательская кривая - ввести параметры вручную")
    print("   Поддержка произвольных GLV кривых")
    
    curve_choice = get_user_input("Выберите кривую (1-3)", "1", int)
    
    if curve_choice == 1:
        # secp256k1
        zvpparams.glv.set_secp256k1()
        print("✓ Установлена кривая secp256k1")
        print(f"✓ Поле: GF({zvpparams.glv.p})")
        print(f"✓ Порядок: {zvpparams.glv.order}")
        print(f"✓ λ (эндоморфизм): {zvpparams.glv.lam}")
        print(f"✓ β (параметр): {zvpparams.glv.beta}")
        
    elif curve_choice == 2:
        # Тестовая кривая p=79, y² = x³ + 7 (mod 67)
        setup_test_curve_p79(zvpparams)
        
    elif curve_choice == 3:
        # Пользовательская кривая
        setup_custom_curve(zvpparams)
        
    else:
        print("❌ Неверный выбор. Используется secp256k1 по умолчанию.")
        zvpparams.glv.set_secp256k1()

def setup_test_curve_p79(zvpparams):
    """Настройка тестовой кривы p=79, y² = x³ + 7 (mod 67)"""
    print("\n--- Настройка тестовой кривой p=79 ---")
    
    # Параметры кривой
    p = 67  # Поле (mod 67)
    a = 0
    b = 7
    
    # Создание кривой
    F = GF(p)
    curve = EllipticCurve(F, [a, b])
    
    # Базовая точка
    base_point = curve(2, 22)
    
    # Проверка что точка на кривой
    assert curve.is_on_curve(2, 22), "Базовая точка не на кривой!"
    
    # Вычисление порядка кривой
    curve_order = curve.order()
    
    print(f"✓ Кривая: y² = x³ + {b} (mod {p})")
    print(f"✓ Базовая точка: {base_point}")
    print(f"✓ Порядок кривой: {curve_order}")
    
    # Попытка найти эндоморфизм для GLV (если возможно)
    try:
        if p % 3 == 1:  # Необходимое условие для GLV эндоморфизма
            # Ищем β такое что β³ ≡ 1 (mod p) и β ≠ 1
            beta = None
            for candidate in range(2, p):
                if pow(candidate, 3, p) == 1 and candidate != 1:
                    beta = candidate
                    break
            
            if beta:
                # Пытаемся вычислить λ
                lambda_val = None
                for candidate in range(1, curve_order):
                    test_point = candidate * base_point
                    if test_point != curve(0):  # Не точка в бесконечности
                        endomorphism_point = curve(beta * test_point[0] % p, test_point[1])
                        if endomorphism_point == candidate * lambda_val * base_point:
                            lambda_val = candidate
                            break
                
                if lambda_val is None:
                    # Простое приближение для тестовой кривой
                    lambda_val = curve_order // 2 + 1
                
                print(f"✓ GLV параметры найдены: β={beta}, λ≈{lambda_val}")
            else:
                beta = 1
                lambda_val = 1
                print("⚠️  GLV эндоморфизм не найден, используются единичные значения")
        else:
            beta = 1
            lambda_val = 1
            print("⚠️  p ≢ 1 (mod 3), GLV эндоморфизм недоступен")
    
    except Exception as e:
        print(f"⚠️  Ошибка вычисления GLV параметров: {e}")
        beta = 1
        lambda_val = 1
    
    # Установка параметров
    zvpparams.glv.curve = curve
    zvpparams.glv.order = curve_order
    zvpparams.glv.lam = ZZ(lambda_val)
    zvpparams.glv.beta = ZZ(beta)
    zvpparams.glv._order_field = GF(curve_order)
    
    # Обновляем битность
    zvpparams.bits = p.nbits()
    
    print(f"✓ Тестовая кривая p=79 настроена успешно")

def setup_custom_curve(zvpparams):
    """Настройка пользовательской кривой"""
    print("\n--- Настройка пользовательской кривой ---")
    
    print("Формат кривой: y² = x³ + ax + b (mod p)")
    
    # Ввод параметров
    p = get_user_input("Простое число p (поле)", "79", int)
    a = get_user_input("Параметр a", "0", int)
    b = get_user_input("Параметр b", "7", int)
    
    try:
        # Создание кривой
        F = GF(p)
        curve = EllipticCurve(F, [a, b])
        curve_order = curve.order()
        
        print(f"✓ Кривая создана: y² = x³ + {a}x + {b} (mod {p})")
        print(f"✓ Порядок кривой: {curve_order}")
        
        # Выбор базовой точки
        use_random_point = get_user_input(
            "Использовать случайную базовую точку? (y/n)", 
            "y", bool
        )
        
        if use_random_point:
            base_point = curve.random_point()
            while base_point == curve(0):  # Избегаем точку в бесконечности
                base_point = curve.random_point()
        else:
            # Ввод координат базовой точки
            base_x = get_user_input("Координата x базовой точки", "2", int)
            base_y = get_user_input("Координата y базовой точки", "22", int)
            
            try:
                base_point = curve(base_x, base_y)
            except:
                print("❌ Неверные координаты точки. Используется случайная точка.")
                base_point = curve.random_point()
        
        print(f"✓ Базовая точка: {base_point}")
        
        # GLV параметры (упрощенные для пользовательской кривой)
        beta = 1
        lambda_val = curve_order // 2 + 1  # Приближение
        
        print("⚠️  Используются упрощенные GLV параметры для пользовательской кривой")
        
        # Установка параметров
        zvpparams.glv.curve = curve
        zvpparams.glv.order = curve_order
        zvpparams.glv.lam = ZZ(lambda_val)
        zvpparams.glv.beta = ZZ(beta)
        zvpparams.glv._order_field = GF(curve_order)
        zvpparams.bits = p.nbits()
        
        print("✓ Пользовательская кривая настроена")
        
    except Exception as e:
        print(f"❌ Ошибка создания кривой: {e}")
        print("Используется secp256k1 по умолчанию")
        zvpparams.glv.set_secp256k1()

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
        
        # Для малых кривых предлагаем малые значения по умолчанию
        if zvpparams.glv.order < 1000:
            default_key = "42"
        else:
            default_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        
        key_input = get_user_input("Приватный ключ", default_key)
        
        try:
            if key_input.startswith('0x') or key_input.startswith('0X'):
                private_key = int(key_input, 16)
            else:
                private_key = int(key_input)
            
            # Проверка что ключ в допустимом диапазоне
            if private_key <= 0 or private_key >= zvpparams.glv.order:
                print(f"⚠️  Ключ вне диапазона [1, {zvpparams.glv.order-1}]. Используется остаток по модулю.")
                private_key = private_key % zvpparams.glv.order
                if private_key == 0:
                    private_key = 1
            
            # Установка ключа
            zvpparams.secrets.k = ZZ(private_key)
            
            # GLV декомпозиция
            try:
                decomp = glv.glv_decompose_simple(
                    private_key, 
                    zvpparams.glv.lam, 
                    zvpparams.glv.order
                )
                zvpparams.secrets.k0 = decomp[0]
                zvpparams.secrets.k1 = decomp[1]
                
                print(f"\n✓ Установлен ключ: {private_key}")
                print(f"✓ GLV декомпозиция: k0={zvpparams.secrets.k0}, k1={zvpparams.secrets.k1}")
                
            except Exception as e:
                print(f"⚠️  Ошибка GLV декомпозиции: {e}")
                print("Устанавливаются упрощенные значения k0, k1")
                zvpparams.secrets.k0 = ZZ(private_key // 2)
                zvpparams.secrets.k1 = ZZ(private_key - zvpparams.secrets.k0)
                
        except ValueError:
            print("❌ Ошибка в формате ключа. Используется случайный ключ.")
            generate_random_key(zvpparams)
    else:
        print("✓ Используется случайно сгенерированный ключ")
        generate_random_key(zvpparams)

def generate_random_key(zvpparams):
    """Генерирует случайный ключ подходящий для выбранной кривой"""
    if zvpparams.glv.curve.base_field().order() > 1000:
        # Для больших кривых используем стандартную генерацию
        zvpparams.generate_secp256k1_secrets()
    else:
        # Для малых кривых генерируем малые ключи
        from random import randint
        max_key = min(zvpparams.glv.order - 1, 100)  # Ограничиваем для малых кривых
        private_key = randint(1, max_key)
        
        zvpparams.secrets.k = ZZ(private_key)
        
        # Упрощенная GLV декомпозиция для малых кривых
        try:
            decomp = glv.glv_decompose_simple(
                private_key, 
                zvpparams.glv.lam, 
                zvpparams.glv.order
            )
            zvpparams.secrets.k0 = decomp[0]
            zvpparams.secrets.k1 = decomp[1]
        except:
            zvpparams.secrets.k0 = ZZ(private_key // 2)
            zvpparams.secrets.k1 = ZZ(private_key - zvpparams.secrets.k0)
        
        print(f"✓ Сгенерирован ключ: {private_key}")
        print(f"✓ k0={zvpparams.secrets.k0}, k1={zvpparams.secrets.k1}")

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
        try:
            zvpparams.registers = utils.load_efd_secp256k1_registers()["modified:mmadd-2009-bl"]
            print("✓ Используются регистры EFD: modified:mmadd-2009-bl")
        except:
            print("⚠️  EFD регистры недоступны для данной кривой. Используются стандартные полиномы.")
            setup_default_polynomials(zvpparams)
    else:
        setup_default_polynomials(zvpparams)

def setup_default_polynomials(zvpparams):
    """Настройка стандартных полиномов"""
    try:
        # Для secp256k1 используем специальные полиномы
        if hasattr(zvpparams.glv, 'curve') and zvpparams.glv.curve.base_field().order() > 1000:
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
        else:
            # Для малых кривых используем простые полиномы
            print("✓ Используются упрощенные полиномы для тестовой кривой")
            X1, Y1, X2, Y2 = zvpparams.registers.gens
            # Добавляем простой полином x1 + x2
            zvpparams.registers.add(X1 + X2)
            
    except Exception as e:
        print(f"⚠️  Ошибка настройки полиномов: {e}")
        print("Используются базовые полиномы")
        X1, Y1, X2, Y2 = zvpparams.registers.gens
        zvpparams.registers.add(X1 + X2)

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
        
        # Выбор кривой (НОВОЕ!)
        setup_curve_selection(zvpparams)
        
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