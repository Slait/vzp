# ZVP-GLV Attack Scripts

Боевые скрипты для атаки Zero-Value Point (ZVP) на GLV-разложение эллиптических кривых.

## Созданные файлы

### 🎯 Основные скрипты атаки

1. **`attack_zvp_glv_inter_easy_prec.py`** - Основной боевой скрипт
   - Требует SageMath и модули из папки `attack/`
   - Выполняет реальную ZVP-GLV атаку
   - Использует предвычисленные данные DCP экспериментов

2. **`attack_zvp_glv_inter_easy_prec_demo.py`** - Демо версия
   - Работает без SageMath
   - Симулирует процесс атаки для демонстрации
   - Показывает интерфейс и функциональность

### 📖 Документация

3. **`zvp_glv_inter_easy_prec.md`** - Полная инструкция
   - Подробное описание атаки
   - Примеры использования
   - Устранение неполадок
   - Техническая документация

4. **`ATTACK_README.md`** - Этот файл (краткая сводка)

## Быстрый старт

### Демо версия (без SageMath)

```bash
# Проверка справки
python3 attack_zvp_glv_inter_easy_prec_demo.py --help

# Базовая атака
python3 attack_zvp_glv_inter_easy_prec_demo.py \
  --pubkey 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 \
  --bits 4 \
  --w 5 \
  --save results.json
```

### Реальная атака (требует SageMath)

```bash
# Установка SageMath
sudo apt-get install sagemath

# Запуск атаки
sage -python attack_zvp_glv_inter_easy_prec.py \
  --pubkey YOUR_PUBKEY_128_HEX_CHARS \
  --bits 4 \
  --w 4 \
  --save attack_results.json
```

**📖 Подробная инструкция по установке SageMath**: см. файл `SETUP_SAGEMATH.md`

## Параметры командной строки

- `--pubkey` - Публичный ключ (128 hex символов или 130 с префиксом '04') **[ОБЯЗАТЕЛЬНО]**
- `--bits` - Количество целевых бит (2-32, по умолчанию: 4)
- `--w` - Размер окна для w-NAF (3-10, по умолчанию: 4)
- `--save` - Сохранить результаты в JSON файл
- `--quiet` - Тихий режим
- `--verify` - Только проверить публичный ключ

## Примеры результатов

### Успешная атака
```
🎯 Атака успешна! Энтропия снижена до 58.5 бит
   Это делает brute-force атаку практически выполнимой!
```

### Частично успешная атака
```
⚠️  Частичный успех: 75.2 бит
   Попробуйте увеличить количество целевых бит
```

### Неуспешная атака
```
❌ Энтропия все еще высока: 210.1 бит
   Атака неэффективна с текущими параметрами
```

## Формат публичного ключа

Публичный ключ должен быть строкой из 128 hex символов:
- Первые 64 символа: X координата точки
- Последние 64 символа: Y координата точки
- Точка должна лежать на кривой secp256k1

Пример (Bitcoin Generator Point):
```
79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

## Структура результатов

JSON файл содержит:
```json
{
  "timestamp": "2024-01-15T14:30:45.123456",
  "attack_type": "zvp_glv_interleaving_easy_precision",
  "target_pubkey": "79BE667E...",
  "target_bits": 25,
  "attack_results": {
    "remaining": 58.5,
    "attack_successful": true
  },
  "success": true
}
```

## Требования

### Для реального скрипта
- SageMath (математическая система)
- Python 3.7+
- Модули в папке `attack/`
- Предвычисленные DCP данные

### Для демо скрипта
- Только Python 3.7+

## Правовая информация

⚠️ **ВНИМАНИЕ**: Скрипты предназначены только для исследовательских и образовательных целей. 

Использование для атак на реальные системы без разрешения владельца является незаконным.

## Устранение проблем

### ❌ "No module named 'sage'"
**Решение**: Установите SageMath или используйте демо версию
```bash
# Установка SageMath
sudo apt-get install sagemath

# Или используйте демо
python3 attack_zvp_glv_inter_easy_prec_demo.py --help
```

### ❌ "module 'utils' has no attribute 'register_submatch'"
**Решение**: Запускайте скрипт из корневой папки проекта
```bash
# Убедитесь, что находитесь в корне проекта
ls attack/  # должна показать файлы attack/

# Запускайте оттуда
sage -python attack_zvp_glv_inter_easy_prec.py --help
```

### ❌ "Публичный ключ должен содержать 128 hex символов"
**Решение**: Скрипт автоматически удаляет префикс '04'
```bash
# Оба варианта корректны:
--pubkey ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac
--pubkey 04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac
```

### ❌ "Отсутствуют предвычисленные данные"
**Решение**: Это нормально, реальная атака требует DCP данных
```bash
# Используйте демо версию для тестирования
python3 attack_zvp_glv_inter_easy_prec_demo.py --pubkey YOUR_KEY --w 4
```

## Поддержка

- 📖 **Полная документация**: `zvp_glv_inter_easy_prec.md`
- 🔧 **Установка SageMath**: `SETUP_SAGEMATH.md`  
- 💻 **Исходный код**: папка `attack/`
- 🧪 **Демо версия**: `attack_zvp_glv_inter_easy_prec_demo.py`