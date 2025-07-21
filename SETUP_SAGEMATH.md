# Установка SageMath для ZVP-GLV атаки

Для работы реального скрипта атаки `attack_zvp_glv_inter_easy_prec.py` требуется установка SageMath.

## Способы установки SageMath

### 1. Ubuntu/Debian

```bash
# Обновляем пакеты
sudo apt-get update

# Устанавливаем SageMath (может занять время)
sudo apt-get install sagemath

# Проверяем установку
sage --version
```

### 2. Conda/Miniconda

```bash
# Создаем новое окружение для sage
conda create -n sage-env -c conda-forge sage

# Активируем окружение
conda activate sage-env

# Проверяем установку
sage --version
```

### 3. Docker (изолированная установка)

```bash
# Скачиваем Docker образ с SageMath
docker pull sagemath/sagemath

# Запускаем контейнер с монтированием текущей папки
docker run -it -v $(pwd):/workspace sagemath/sagemath

# Внутри контейнера переходим в папку и запускаем скрипт
cd /workspace
sage -python attack_zvp_glv_inter_easy_prec.py --help
```

### 4. Установка из исходного кода

```bash
# Клонируем репозиторий (требует много времени и ресурсов)
git clone https://github.com/sagemath/sage.git
cd sage

# Компилируем (может занять несколько часов!)
make

# Добавляем в PATH
export PATH="$PWD:$PATH"
```

## Запуск скрипта атаки

После установки SageMath используйте один из следующих способов:

### Способ 1: Через sage -python

```bash
sage -python attack_zvp_glv_inter_easy_prec.py \
  --pubkey YOUR_PUBKEY_128_HEX_CHARS \
  --w 4 \
  --bits 4
```

### Способ 2: В интерактивной сессии SageMath

```bash
# Запускаем SageMath
sage

# В интерактивной сессии выполняем:
exec(open('attack_zvp_glv_inter_easy_prec.py').read())
```

### Способ 3: Jupyter notebook с SageMath ядром

```bash
# Запускаем Jupyter с SageMath ядром
sage -n jupyter

# Создаем новый notebook с SageMath ядром
# Импортируем и запускаем скрипт
```

## Проверка корректности установки

Создайте тестовый файл `test_sage.py`:

```python
try:
    from sage.all import ZZ, EllipticCurve, GF
    print("✅ SageMath установлен корректно")
    
    # Тестируем базовую функциональность
    E = EllipticCurve(GF(101), [2, 3])
    print(f"✅ Эллиптическая кривая создана: {E}")
    
except ImportError as e:
    print(f"❌ SageMath не установлен: {e}")
```

Запустите тест:

```bash
sage -python test_sage.py
```

## Альтернатива: Демо версия

Если установка SageMath вызывает трудности, используйте демо версию скрипта:

```bash
python3 attack_zvp_glv_inter_easy_prec_demo.py \
  --pubkey YOUR_PUBKEY_128_HEX_CHARS \
  --w 4 \
  --bits 4
```

Демо версия симулирует процесс атаки и не требует SageMath.

## Устранение проблем

### Проблема: "No module named 'sage'"

**Решение**: SageMath не установлен или не в PATH
- Проверьте: `sage --version`
- Переустановите SageMath
- Используйте: `sage -python` вместо `python3`

### Проблема: "module 'utils' has no attribute 'register_submatch'"

**Решение**: Неправильный импорт модулей атаки
- Убедитесь, что папка `attack/` находится в той же директории
- Запускайте скрипт из корневой папки проекта

### Проблема: Медленная работа

**Решение**: SageMath может работать медленно на первом запуске
- Используйте `--quiet` для уменьшения вывода
- Начните с малых значений `--w` и `--bits`

### Проблема: Недостаточно памяти

**Решение**: Атака может требовать много памяти
- Закройте другие приложения
- Используйте меньшие значения параметров
- Рассмотрите использование Docker с ограничениями памяти

## Производительность

Ориентировочное время выполнения на современном ПК:

- `--w 3 --bits 4`: 1-5 минут
- `--w 4 --bits 4`: 5-15 минут  
- `--w 5 --bits 4`: 15-30 минут

Время зависит от:
- Производительности процессора
- Объема доступной памяти
- Наличия предвычисленных данных DCP

## Поддержка

При возникновении проблем:

1. Проверьте версию SageMath: `sage --version`
2. Убедитесь в наличии всех файлов в папке `attack/`
3. Запустите демо версию для проверки логики
4. Используйте параметр `--verify` для проверки публичного ключа

Для отладки добавьте параметр `--verbose` (если поддерживается) или уберите `--quiet` для получения подробного вывода.