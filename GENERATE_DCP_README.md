# Генератор предвычисленных DCP точек

Этот генератор создает предвычисленные DCP (Dependent Coordinates Problem) точки, необходимые для выполнения ZVP-GLV атаки.

## Что генерирует

Генератор создает два типа файлов в папке `attack/results/`:

1. **DCP эксперименты**: `interleaving_dcp_experiment_256_TIMESTAMP.json`
   - Результаты решения DCP для различных w-NAF комбинаций
   - Содержит найденные точки и метаданные

2. **Remapped точки**: `interleaving_secp256k1_remapped_W.json`
   - Точки, сопоставленные с их w-NAF представлениями
   - Используются основным скриптом атаки для "Этап 1"

## Быстрый старт

### Демо-версия (без SageMath)

```bash
# Быстрая демонстрация
python3 generate_dcp_points_demo.py \
  --pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac \
  --w 4 \
  --experiments 50

# Несколько размеров окон
python3 generate_dcp_points_demo.py \
  --pubkey YOUR_PUBKEY \
  --w 3 4 5 \
  --experiments 100
```

### Реальная версия (требует SageMath)

```bash
# Установка SageMath
sudo apt-get install sagemath

# Генерация для w=4 (рекомендуется)
sage -python generate_dcp_points.py \
  --pubkey YOUR_PUBKEY_128_HEX_CHARS \
  --w 4 \
  --experiments 1000

# Полная генерация для исследования
sage -python generate_dcp_points.py \
  --pubkey YOUR_PUBKEY \
  --w 3 4 5 \
  --full
```

## Основные параметры

- `--pubkey` - Публичный ключ (128 hex или 130 с '04')
- `--w` - Размеры окон w-NAF (3-10, по умолчанию: 4)
- `--experiments` - Количество экспериментов (по умолчанию: 1000)
- `--polynomial` - Индекс полинома secp256k1 (0-12, по умолчанию: 0)
- `--full` - Генерация всех возможных комбинаций
- `--quiet` - Тихий режим

## Рекомендуемые значения w

Согласно Figure 6 научной работы (Appendix 6.2):

- **w=3**: Быстро, но меньше эффективность
- **w=4**: Оптимальный баланс (рекомендуется)
- **w=5**: Более эффективно, но медленнее

## Процесс генерации

### Этап 1: DCP эксперименты
Генератор создает эксперименты для всех возможных комбинаций w-NAF значений:
- Для w=4: 16×16 = 256 комбинаций
- Решает DCP (Dependent Coordinates Problem) для каждой пары (w0, w1)
- Находит точки, удовлетворяющие условиям zero-value

### Этап 2: Remapping точек
Найденные точки сопоставляются с их w-NAF скалярами:
- Проверяется условие `registers.is_zero(P, Q)` для всех комбинаций
- Создается mapping точка → список скаляров
- Сохраняется в формате, совместимом с основным скриптом атаки

## Время выполнения

Ориентировочное время на современном ПК с SageMath:

| Параметры | Время (демо) | Время (реальное) |
|-----------|--------------|------------------|
| w=3, 100 экспериментов | 1-2 секунды | 5-10 минут |
| w=4, 1000 экспериментов | 3-5 секунд | 30-60 минут |
| w=5, полная генерация | 10-20 секунд | 2-4 часа |

## Использование результатов

После генерации точек можно запускать основную атаку:

```bash
# Убедитесь, что файлы созданы
ls attack/results/interleaving_secp256k1_remapped_4.json

# Запустите атаку
sage -python attack_zvp_glv_inter_easy_prec.py \
  --pubkey YOUR_PUBKEY \
  --w 4 \
  --bits 4
```

## Управление ресурсами

### Память
- Каждый эксперимент может потреблять 10-100MB памяти
- Для больших значений w используйте `--experiments` для ограничения

### Диск
- DCP файлы: 1-10MB для 1000 экспериментов
- Remapped файлы: 1-50MB в зависимости от найденных точек

### CPU
- SageMath интенсивно использует CPU
- Параллелизация не реализована (возможно в будущем)

## Отладка

### Проверка работы демо-версии
```bash
python3 generate_dcp_points_demo.py --pubkey YOUR_KEY --w 4 --experiments 10 --quiet
echo "Статус: $?"  # Должно быть 0
```

### Проверка созданных файлов
```bash
# Проверка структуры DCP файла
python3 -c "
import json
with open('attack/results/interleaving_dcp_experiment_256_demo_*.json') as f:
    data = json.load(f)
    print(f'Метаданные: {data[\"metadata\"]}')
    print(f'Результатов: {len(data[\"results\"])}')
"

# Проверка remapped файла
python3 -c "
import json
with open('attack/results/interleaving_secp256k1_remapped_4_demo.json') as f:
    data = json.load(f)
    print(f'Записей: {len(data)}')
    print(f'Точек в первой записи: {len(data[0][\"points\"])}')
"
```

## Автоматизация

Для автоматической генерации точек для исследования:

```bash
#!/bin/bash
# generate_all_points.sh

PUBKEY="YOUR_PUBKEY_HERE"

for w in 3 4 5; do
    echo "Генерация для w=$w..."
    sage -python generate_dcp_points.py \
        --pubkey "$PUBKEY" \
        --w "$w" \
        --experiments 500 \
        --quiet
done

echo "Генерация завершена. Файлы в attack/results/"
ls -la attack/results/interleaving_secp256k1_remapped_*.json
```

## Связанные файлы

- `generate_dcp_points.py` - Основной генератор (требует SageMath)
- `generate_dcp_points_demo.py` - Демо-версия (без SageMath)
- `attack_zvp_glv_inter_easy_prec.py` - Использует созданные точки
- `SETUP_SAGEMATH.md` - Инструкция по установке SageMath

## Устранение проблем

См. файл `SETUP_SAGEMATH.md` и раздел "Устранение проблем" в `ATTACK_README.md`.