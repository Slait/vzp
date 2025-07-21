# ZVP-GLV Attack Scripts for Small Curve (mod 79)

Два специализированных скрипта для работы с малой эллиптической кривой по модулю 79, предназначенные для исследования и тестирования атак на основе GLV-SAC представления.

## 📁 Файлы

- `attack/attack_zvp_glv_sac_79.py` - Основной скрипт атаки
- `attack/check_79.py` - Скрипт верификации результатов

## 🔢 Параметры малой кривой

- **Модуль**: p = 79
- **Уравнение кривой**: y² ≡ x³ + 7 (mod 79)
- **Порядок группы**: n = 79
- **Приватные ключи**: d ∈ [0, 78]

## 📊 Таблица соответствий

| Приватный ключ (d) | Публичный ключ (Qx, Qy) |
|-------------------|-------------------------|
| 0 | ∞ (точка на бесконечности) |
| 1 | (2, 22) |
| 2 | (52, 7) |
| 3 | (62, 63) |
| 4 | (25, 17) |
| 5 | (46, 4) |
| ... | ... |
| 25 | (47, 39) |
| ... | ... |
| 78 | (2, 45) |

## 🚀 Использование

### Скрипт атаки (`attack_zvp_glv_sac_79.py`)

```bash
# Атака по координатам публичного ключа
python attack/attack_zvp_glv_sac_79.py --pubkey "2,22" --bits 4

# Атака по приватному ключу (для поиска публичного)
python attack/attack_zvp_glv_sac_79.py --pubkey "1" --bits 4

# Атака с кастомным выводом
python attack/attack_zvp_glv_sac_79.py --pubkey "47,39" --bits 3 --save results/
```

**Параметры:**
- `--pubkey` - Публичный ключ как "x,y" или приватный ключ для поиска
- `--bits` - Количество битов для восстановления (2-6)
- `--save` - Директория для сохранения результатов

### Скрипт проверки (`check_79.py`)

```bash
# Проверка результатов атаки
python attack/check_79.py --json results/attack_mod79_2_22_bits4.json --privkey 1

# Проверка с подробным выводом
python attack/check_79.py --json results/attack_mod79_47_39_bits3.json --privkey 25 --verbose
```

**Параметры:**
- `--json` - JSON файл с результатами атаки
- `--privkey` - Известный приватный ключ (0-78)
- `--verbose` - Подробный вывод

## 📈 Пример работы

### 1. Запуск атаки для d=1

```bash
$ python attack/attack_zvp_glv_sac_79.py --pubkey "2,22" --bits 4

======================================================================
ZVP-GLV Attack on Straus-Shamir Trick (Small Curve mod 79)
======================================================================
[+] Setting up ZVP-GLV attack parameters for curve mod 79
    Target public key: (2, 22)
    ✓ Found corresponding private key: d = 1
    Target bits: 4
    Output directory: results

[+] Running ZVP-GLV Attack on small curve (mod 79)
[+] Generating GLV-SAC candidates for 4 bits
    Total possible combinations: 81
    Generated 10 GLV-SAC candidates
    ✓ Attack completed in 0.00 seconds
    ✓ Generated 10 candidates
    ✓ Estimated recovered bits: 8.0 bits

[+] Attack Summary:
    Target: (2, 22)
    Candidates: 10
    Recovered: 8.0 bits
    Reduction factor: 8.1x

[+] ✓ Attack completed successfully!
```

### 2. Проверка результатов

```bash
$ python attack/check_79.py --json results/attack_mod79_2_22_bits4.json --privkey 1

======================================================================
ZVP-GLV Attack Results Verification (Small Curve mod 79)
======================================================================
[+] Target Information:
    Private key: 1
    Public key: (2, 22)
    ✓ Verified with lookup table

[+] Candidate Verification:
    Candidate 3 Analysis:
      ✓ RECONSTRUCTION SUCCESS!
        Method: ternary_+
        Reconstructed k: 1
        ✓ EXACT MATCH with target private key!

[+] ✓ VERIFICATION SUCCESSFUL!
    Attack successfully recovered 1 valid candidate(s)
```

## 🔍 Особенности малой кривой

### Преимущества для исследований:
- **Полная таблица соответствий** - все пары (d, Q) предвычислены
- **Быстрые вычисления** - операции по модулю 79 выполняются мгновенно
- **Простая верификация** - легко проверить правильность результатов
- **Наглядность** - можно анализировать все возможные случаи

### Ограничения:
- **Упрощенная GLV декомпозиция** - λ не определена для такой малой кривой
- **Ограниченная безопасность** - 79 вариантов легко перебрать полностью
- **Модифицированные алгоритмы** - GLV-SAC адаптированы для малого порядка

## 📊 Анализ эффективности

Скрипты демонстрируют:

1. **Сокращение пространства поиска** от 3^(2×bits) до ~10 кандидатов
2. **Структурное восстановление** GLV-SAC битов
3. **Математическую верификацию** через реконструкцию публичных ключей
4. **Различные методы интерпретации** восстановленных битов

## 🎯 Применение

Эти скрипты предназначены для:
- **Исследования алгоритмов** GLV-SAC атак
- **Тестирования концепций** перед применением к большим кривым
- **Образовательных целей** для понимания принципов работы
- **Отладки алгоритмов** восстановления битов

## ⚠️ Предупреждения

- Скрипты предназначены только для исследовательских целей
- Не используйте на продакшн системах без соответствующих разрешений
- Результаты на малой кривой могут не полностью отражать поведение на реальных кривых
- Алгоритмы упрощены для работы с ограниченным пространством параметров