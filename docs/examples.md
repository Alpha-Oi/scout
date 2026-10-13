# Примеры и рецепты

Все примеры проверены на реальном запуске. Быстрее всего увидеть их самому:

```sh
python examples/demo.py          # путь к дашборду печатается в конце
python examples/demo.py --open   # и сразу открыть в браузере
```

Демо создаёт во временной папке мини-проект с типичными проблемами, сканирует
его, «чинит» и сканирует повторно. Ваши файлы не затрагиваются.

## Пример 1. Что находит Scout

Исходный учебный проект (`app.py`):

```python
import os
import subprocess

API_KEY = "sk-live-..."            # <- ключ в коде

def run(cmd):
    # TODO: validate input
    return subprocess.run(cmd, shell=True)

def load(expr):
    return eval(expr)              # <- eval пользовательского ввода
```

Результат скана (12 детекторов: все, кроме `semgrep` и медленных `pytest-failed` и
`pip-audit`, которые пропускает `--quick`; путь к папке прогона сокращён):

```
scout: 9 findings → reports/run-1  (3.6s)
  critical 1
  high     1
  medium   3
  low      4
```

| Severity | Детектор | Где | Предложение Scout (сокращённо) |
|---|---|---|---|
| critical | `secrets` | `app.py:4` | Если это секрет: перенести в `.env`, добавить `.env` в `.gitignore`, ротировать ключ у провайдера |
| high | `bandit` | `app.py:9` | `subprocess` с `shell=True` (B602): заменить на вызов без shell |
| medium | `detect-secrets` | `app.py:4` | Тот же ключ, найденный по энтропии: ротировать, вынести в `.env` |
| medium | `bandit` | `app.py:13` | `eval` (B307): заменить на `ast.literal_eval` |
| medium | `interrogate` | `app.py` | Нет docstring (0%, 3 пропущено): добавить |
| low | `ruff` | `app.py:1` | F401, неиспользуемый импорт: `ruff check --fix`, затем проверить diff |
| low | `vulture` | `app.py:1` | Тот же `import os` как мёртвый код: проверить `grep`, удалить |
| low | `ruff` | `app.py:9` | PLW1510: `subprocess.run` без `check` |
| low | `todo-fixme` | `app.py:8` | Реализовать пометку или удалить |

Обратите внимание: один и тот же ключ нашли два независимых детектора (`secrets` по
шаблону имени, `detect-secrets` по энтропии), а `import os` увидели `ruff` и `vulture`.
Это не ошибка: детекторы независимы, а дубли удобно отсеивать во вкладке «По коду».

## Пример 2. Было → стало (diff)

После исправлений (ключ из окружения, `ast.literal_eval`, `check=True`, без `shell=True`):

```
scout: 2 findings → reports/run-2  (2.1s)
  medium   1
  low      1

diff: new=1 fixed=8 same=1
```

Исправлено восемь находок. Осталась одна старая (`interrogate`: docstring так и нет,
в diff она «не изменилась») и появилась одна новая: оставленный `TODO: add timeout`.
В дашборде на вкладке **Diff** они помечены как *fixed*, *same* и *new*.

## Рецепт: проверка перед релизом

```sh
python tools/scan.py . --out /tmp/scout-reports
```

Смотрите сначала `critical` и `high`; остальное не блокирует релиз.

## Рецепт: «покажи только уязвимости»

В дашборде введите в поиск `vuln`, либо отключите лишние детекторы:

```json
{ "skip_detectors": ["ruff", "radon", "interrogate", "vulture", "pyscn", "pip-outdated", "todo-fixme"] }
```

## Рецепт: быстрый скан большого проекта

```sh
python tools/scan.py ~/big-project --out ./reports --quick --max-findings 300
```

`--quick` пропускает самые медленные детекторы (`pytest-failed`, `pip-audit`).

## Рецепт: отправить находки в GitHub Code Scanning

В дашборде нажмите «↓ SARIF», затем загрузите файл через
`github/codeql-action/upload-sarif` или в разделе *Security → Code scanning*.

## Рецепт: отправить находки коллегам

Экспорт «↓ Markdown» (или «Markdown в буфер») из дашборда вставляется в issue, PR или чат.
Одну находку можно передать ИИ-агенту кнопкой «Скопировать задачу».

## Рецепт: скан по расписанию в GitHub Actions

Готовый пример лежит в [`.github/workflows/scout-self-scan.yml`](../.github/workflows/scout-self-scan.yml):
Scout сканирует сам себя каждую ночь и выкладывает отчёт артефактом. Для своего проекта:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.11" }
- run: |
    git clone --depth 1 https://github.com/Alpha-Oi/scout.git /tmp/scout
    python /tmp/scout/tools/doctor.py --yes
    python /tmp/scout/tools/scan.py . --out reports
- uses: actions/upload-artifact@v4
  with: { name: scout-report, path: reports/ }
```

> `tools/summary.py` читает каталог `reports/` в текущей папке. Это сделано
> под CI, а не общий инструмент. Без параметров он печатает счётчики по серьёзности,
> а `python tools/summary.py --list critical high` печатает таблицу самых серьёзных
> находок (детектор, файл:строка, заголовок; сырой вывод детекторов и значения
> секретов не печатаются). Так их видно прямо в логе шага и в сводке запуска.

## Рецепт: от находки до исправления

```sh
cd ~/projects/my-app
python /path/to/scout/tools/queue.py /path/to/reports/<прогон> --severity high --limit 5
ls .scout-queue/pending/
```

Откройте любой `task-*.md`, исправьте, прогоните команды из блока `verify`,
перенесите файл в `.scout-queue/done/`, пересканируйте и посмотрите diff.

## Пример кейса: GPTMemoryEngine

Реальный проект на ~200 строк Python (RAG-память).

| Этап | critical | high | medium | low | **Всего** |
|---|---|---|---|---|---|
| Первый скан | 0 | **5** | 7 | 11 | **23** |
| После исправлений | 0 | **0** | 2 | 4 | **6** |

Исправлено: CVE в `PyPDF2` (переход на `pypdf`), 7 ошибок `mypy`, 4 замечания `ruff`,
сортировка импортов. Метод: скан → очередь → исправление → пересканирование → diff.
