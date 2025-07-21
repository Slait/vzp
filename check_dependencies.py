#!/usr/bin/env python3
"""
Проверка всех зависимостей для ZVP-GLV атаки
"""

import os
import sys
import subprocess


def check_sage():
    """Проверка SageMath"""
    print("🧮 Проверка SageMath...")
    try:
        result = subprocess.run(['sage', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"   ✅ SageMath установлен: {version}")
            return True
        else:
            print(f"   ❌ SageMath недоступен")
            return False
    except FileNotFoundError:
        print(f"   ❌ Команда 'sage' не найдена")
        return False
    except subprocess.TimeoutExpired:
        print(f"   ❌ Timeout при проверке SageMath")
        return False
    except Exception as e:
        print(f"   ❌ Ошибка проверки SageMath: {e}")
        return False


def check_pari():
    """Проверка PARI/GP"""
    print("\n🔢 Проверка PARI/GP...")
    try:
        result = subprocess.run(['gp', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            print(f"   ✅ PARI/GP установлен: {version}")
            return True
        else:
            print(f"   ❌ PARI/GP недоступен")
            return False
    except FileNotFoundError:
        print(f"   ❌ Команда 'gp' не найдена")
        return False
    except Exception as e:
        print(f"   ❌ Ошибка проверки PARI/GP: {e}")
        return False


def check_pari_tools():
    """Проверка pari_tools"""
    print("\n🛠️  Проверка pari_tools...")
    
    # Проверяем наличие папки
    pari_dir = './attack/pari_tools'
    if not os.path.exists(pari_dir):
        print(f"   ❌ Папка {pari_dir} не найдена")
        return False
    
    print(f"   ✅ Папка {pari_dir} найдена")
    
    # Проверяем solver файлы
    solvers = ['dcp_solver', 'dcp_glv_solver', 'multidcp_solver', 'multidcp_glv_solver']
    all_ok = True
    
    for solver in solvers:
        solver_path = f"{pari_dir}/{solver}"
        if os.path.exists(solver_path):
            if os.access(solver_path, os.X_OK):
                print(f"   ✅ {solver}: найден и исполняемый")
                
                # Проверяем зависимости
                try:
                    result = subprocess.run([solver_path], capture_output=True, text=True, timeout=2)
                    if result.returncode == 127:
                        print(f"   ⚠️  {solver}: отсутствуют библиотеки PARI/GP")
                        all_ok = False
                    else:
                        print(f"   ✅ {solver}: работает корректно")
                except subprocess.TimeoutExpired:
                    print(f"   ✅ {solver}: запускается (timeout это норма)")
                except Exception as e:
                    print(f"   ⚠️  {solver}: ошибка при запуске: {e}")
                    all_ok = False
            else:
                print(f"   ❌ {solver}: не исполняемый")
                all_ok = False
        else:
            print(f"   ❌ {solver}: не найден")
            all_ok = False
    
    # Проверяем папку results
    results_dir = f"{pari_dir}/results"
    if os.path.exists(results_dir):
        print(f"   ✅ Папка results найдена")
    else:
        print(f"   ⚠️  Папка results отсутствует (будет создана автоматически)")
    
    return all_ok


def check_attack_folder():
    """Проверка папки attack"""
    print("\n📁 Проверка папки attack...")
    
    if not os.path.exists('./attack'):
        print("   ❌ Папка attack не найдена")
        return False
    
    required_files = ['utils.py', 'dcp.py', 'glv.py', 'msm.py', 'zvp_glv_inter_easy_prec.py']
    all_ok = True
    
    for file in required_files:
        file_path = f"./attack/{file}"
        if os.path.exists(file_path):
            print(f"   ✅ {file}: найден")
        else:
            print(f"   ❌ {file}: не найден")
            all_ok = False
    
    return all_ok


def check_python_version():
    """Проверка версии Python"""
    print("🐍 Проверка Python...")
    version = sys.version_info
    print(f"   ✅ Python {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("   ⚠️  Рекомендуется Python 3.8+")
        return False
    
    return True


def main():
    print("🔍 Проверка зависимостей ZVP-GLV атаки")
    print("=" * 50)
    
    results = {
        'python': check_python_version(),
        'attack_folder': check_attack_folder(),
        'sage': check_sage(),
        'pari': check_pari(),
        'pari_tools': check_pari_tools()
    }
    
    print("\n📊 Сводка результатов:")
    print("-" * 30)
    
    all_ok = True
    for component, status in results.items():
        status_str = "✅ OK" if status else "❌ FAIL"
        print(f"   {component:12}: {status_str}")
        if not status:
            all_ok = False
    
    print("\n🎯 Рекомендации:")
    
    if not results['sage']:
        print("   📝 Установите SageMath для реальной атаки:")
        print("      sudo apt-get install sagemath")
        print("   🎭 Или используйте демо-версию для тестирования")
    
    if not results['pari']:
        print("   📝 Установите PARI/GP для DCP решений:")
        print("      sudo apt-get install pari-gp libpari-dev")
    
    if not results['pari_tools']:
        print("   📝 Проверьте права доступа pari_tools:")
        print("      chmod +x attack/pari_tools/*_solver")
    
    if not results['attack_folder']:
        print("   📝 Убедитесь, что папка attack/ находится в корне проекта")
    
    if all_ok:
        print("\n🎉 Все зависимости готовы!")
        print("   Можно запускать: sage -python generate_dcp_points.py")
    else:
        print("\n⚠️  Некоторые компоненты недоступны")
        print("   Демо версия: python3 generate_dcp_points_demo.py")
    
    return all_ok


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)