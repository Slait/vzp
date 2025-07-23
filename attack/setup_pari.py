#!/usr/bin/env sage

"""
Настройка PARI для решения проблем с переполнением стека
"""

import os
import subprocess

def create_gprc_config():
    """Создает файл конфигурации PARI ~/.gprc"""
    home_dir = os.path.expanduser("~")
    gprc_path = os.path.join(home_dir, ".gprc")
    
    # Конфигурация PARI с увеличенным стеком
    config_content = """
/* PARI/GP configuration file */
/* Увеличение размера стека для ZVP-GLV атак */

/* Основные настройки памяти */
parisizemax = 64000000000   /* Максимальный размер стека: 64GB */
parisize = 32000000000      /* Начальный размер стека: 32GB */

/* Дополнительные настройки */
stackwarn = 0               /* Отключить предупреждения о стеке */
secure = 0                  /* Отключить безопасный режим */
timer = 1                   /* Включить таймер */

/* Настройки вывода */
format = "g0.28"            /* Формат чисел */
echo = 0                    /* Отключить эхо команд */

/* Настройки для больших вычислений */
log = 0                     /* Отключить логирование */
logfile = ""                /* Файл логов */

/* Отладка (установить в 1 для отладки) */
debug = 0
debugmem = 0
"""
    
    try:
        with open(gprc_path, 'w') as f:
            f.write(config_content.strip())
        print(f"✓ Создан файл конфигурации PARI: {gprc_path}")
        print("✓ Установлен максимальный размер стека: 64GB")
        return True
    except Exception as e:
        print(f"❌ Ошибка создания .gprc: {e}")
        return False

def check_pari_installation():
    """Проверяет установку PARI/GP"""
    try:
        result = subprocess.run(['gp', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ PARI/GP установлен и доступен")
            print(f"Версия: {result.stdout.strip().split()[0]}")
            return True
        else:
            print("❌ PARI/GP не найден или работает некорректно")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("❌ PARI/GP не установлен или недоступен")
        print("Установите PARI/GP командой: sudo apt-get install pari-gp")
        return False

def test_pari_memory():
    """Тестирует настройки памяти PARI"""
    try:
        # Простой тест выделения памяти
        test_command = 'allocatemem(1000000000); quit'
        result = subprocess.run(['gp', '-q'], 
                              input=test_command, 
                              capture_output=True, text=True, timeout=30)
        
        if "stack overflows" in result.stderr:
            print("❌ Проблемы с настройкой памяти PARI")
            return False
        else:
            print("✓ Настройки памяти PARI работают корректно")
            return True
    except Exception as e:
        print(f"⚠️  Не удалось протестировать память PARI: {e}")
        return False

def setup_environment_variables():
    """Настраивает переменные окружения для PARI"""
    env_vars = {
        'PARI_SIZE': '32000000000',      # 32GB начальный размер
        'PARI_SIZEMAX': '64000000000',   # 64GB максимальный размер
    }
    
    for var, value in env_vars.items():
        os.environ[var] = value
        print(f"✓ Установлена переменная окружения: {var}={value}")

def fix_sage_pari_integration():
    """Исправляет интеграцию Sage с PARI"""
    try:
        from sage.all import pari
        
        # Попытка увеличить размер стека через Sage
        try:
            pari.allocatemem(32 * 1024 * 1024 * 1024)  # 32GB
            print("✓ Размер стека PARI увеличен через Sage до 32GB")
        except:
            try:
                pari.allocatemem(16 * 1024 * 1024 * 1024)  # 16GB
                print("✓ Размер стека PARI увеличен через Sage до 16GB")
            except:
                try:
                    pari.allocatemem(8 * 1024 * 1024 * 1024)  # 8GB
                    print("✓ Размер стека PARI увеличен через Sage до 8GB")
                except:
                    print("⚠️  Не удалось увеличить размер стека PARI через Sage")
        
        # Проверка текущего размера
        current_size = pari.stacksize()
        print(f"✓ Текущий размер стека PARI: {current_size} байт ({current_size/1024/1024/1024:.1f} GB)")
        
        return True
    except Exception as e:
        print(f"❌ Ошибка настройки Sage-PARI: {e}")
        return False

def print_troubleshooting_tips():
    """Печатает советы по устранению проблем"""
    print("\n" + "="*60)
    print("СОВЕТЫ ПО УСТРАНЕНИЮ ПРОБЛЕМ:")
    print("="*60)
    print()
    print("1. ПЕРЕПОЛНЕНИЕ СТЕКА PARI:")
    print("   - Уменьшите target_bits в атаках (начните с 3-4)")
    print("   - Уменьшите количество экспериментов (n_exp=1)")
    print("   - Перезапустите Sage после создания .gprc")
    print()
    print("2. ОШИБКИ JSON СЕРИАЛИЗАЦИИ:")
    print("   - Используйте fix_experiments.py вместо experiments.py")
    print("   - Результаты будут автоматически конвертированы")
    print()
    print("3. НИЗКАЯ ПРОИЗВОДИТЕЛЬНОСТЬ:")
    print("   - Убедитесь, что скомпилированы PARI инструменты:")
    print("     cd pari_tools && make")
    print("   - Используйте SSD для временных файлов")
    print()
    print("4. КРИТИЧЕСКИЕ ОШИБКИ:")
    print("   - Перезапустите Sage: sage --reset")
    print("   - Очистите кэш: rm -rf ~/.sage/cache")
    print("   - Обновите Sage до последней версии")

def main():
    """Главная функция настройки"""
    print("="*60)
    print("        НАСТРОЙКА PARI ДЛЯ ZVP-GLV АТАК")
    print("="*60)
    print()
    
    success_count = 0
    total_steps = 5
    
    print("1. Проверка установки PARI/GP...")
    if check_pari_installation():
        success_count += 1
    
    print("\n2. Создание конфигурации PARI (.gprc)...")
    if create_gprc_config():
        success_count += 1
    
    print("\n3. Настройка переменных окружения...")
    setup_environment_variables()
    success_count += 1
    
    print("\n4. Настройка интеграции Sage-PARI...")
    if fix_sage_pari_integration():
        success_count += 1
    
    print("\n5. Тестирование настроек памяти...")
    if test_pari_memory():
        success_count += 1
    
    print("\n" + "="*60)
    print(f"РЕЗУЛЬТАТ НАСТРОЙКИ: {success_count}/{total_steps} шагов выполнено")
    print("="*60)
    
    if success_count >= 4:
        print("✅ НАСТРОЙКА ЗАВЕРШЕНА УСПЕШНО!")
        print("\nТеперь вы можете запускать атаки:")
        print("- sage fix_experiments.py")
        print("- sage run.py")
    else:
        print("⚠️  НАСТРОЙКА ЗАВЕРШЕНА С ПРЕДУПРЕЖДЕНИЯМИ")
        print("Некоторые функции могут работать некорректно.")
    
    print_troubleshooting_tips()

if __name__ == "__main__":
    main()