# Настройка: `.scoutrc`

Необязательный JSON-файл в **корне сканируемого проекта** (не в папке Scout).
Scout его только читает. Без файла работают значения по умолчанию.

Готовый шаблон: [`.scoutrc.example`](../.scoutrc.example). Скопируйте его:

```sh
cp /path/to/scout/.scoutrc.example ~/projects/my-app/.scoutrc
```

## Все параметры

| Ключ | Тип | Что делает |
|---|---|---|
| `skip_detectors` | список имён | полностью отключает перечисленные [детекторы](detectors.md) |
| `severity_rules` | `{детектор: уровень}` | переопределяет severity **всех** находок детектора (`critical`, `high`, `medium`, `low`) |
| `max_findings` | число или `null` | общий потолок находок за прогон (флаг `--max-findings` важнее) |
| `max_findings_per_detector` | `{детектор: число}` | потолок для отдельного детектора |
| `bandit_skip` | список кодов | правила bandit, которые не нужны (например `B101`) |

## Формат файла

Обычный JSON, но Scout прощает две вещи:

- **висячие запятые** перед `}` и `]`;
- **комментарии**: любой ключ, начинающийся с `_`, игнорируется:

```json
{
  "_comment": "Монорепо: pyscn тут слишком шумный",
  "skip_detectors": ["pyscn"],
  "severity_rules": { "todo-fixme": "low", },
}
```

Если файл не разбирается, Scout пишет `scout: .scoutrc parse error: ...` в stderr
и продолжает с настройками по умолчанию. Это не ошибка сканирования, но ваши
правила в этом прогоне **не применились**.

## Типовые сценарии

**«Слишком много шума от стиля»**

```json
{ "max_findings_per_detector": { "ruff": 100, "interrogate": 50 } }
```

**«Нужно только то, что реально может сломать»**

```json
{ "skip_detectors": ["ruff", "radon", "interrogate", "vulture", "pyscn", "pip-outdated", "todo-fixme"] }
```

**«TODO в моём проекте это нормально, но не теряйте их»**

```json
{ "severity_rules": { "todo-fixme": "low" } }
```

**«Скан в CI не должен ходить в сеть и гонять тесты»**

Используйте флаг `--quick` (пропускает `pytest-failed` и `pip-audit`), а не конфиг.

## Отдельно от `.scoutrc`

| Что | Где |
|---|---|
| Каталог отчётов | `--out DIR` у `scan.py` (по умолчанию `./.scout`) |
| Очередь задач | `--queue DIR` у `queue.py` (по умолчанию `./.scout-queue`) |
| LLM-провайдер | переменные окружения `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` или локальный Ollama |
| Кэш LLM | `.scout-llm-cache.json` в текущем каталоге |
