import json, textwrap, zipfile, subprocess
from prettytable import PrettyTable

def wrap_text(text, width):
    if text:
        wrapped_text = textwrap.fill(text, width)
    else:
        "error"
    return wrapped_text


GITHUB_REPO_URL = "https://github.com/ShiftLeftSecurity/shiftleft-go-demo/archive/refs/heads/master.zip"
ARCHIVE_PATH = "scanning_repo.zip"
SCAN_DIR = "./scan-dir"
SEMGREP_RULES = '--config=auto'
SEMGREP_EXCLUDE = '--exclude-rule=go.gorilla.security.audit.session-cookie-missing-httponly.session-cookie-missing-httponly'

# Скачиваем репозиторий
subprocess.run(['wget', GITHUB_REPO_URL, '-O', ARCHIVE_PATH])

# Распаковываем 
with zipfile.ZipFile(ARCHIVE_PATH, 'r') as zip_file:
    zip_file.extractall(SCAN_DIR)

# Сканируем с помощью semgrep
semgrep_result = subprocess.run(['semgrep', 'scan', SEMGREP_RULES, SEMGREP_EXCLUDE, '--json', SCAN_DIR], stdout=subprocess.PIPE)
semgrep_json_result = json.loads(semgrep_result.stdout)

# Преобразовываем в json
results = semgrep_json_result.get('results', [])

# Обозначаем подключаемы плагин для таблиц
table = PrettyTable()

# Определяем столбцы
table.field_names = ["Vulnerability class", "Path", "CWE", "Severity"]

# Преобразовываем json в таблицу
for result in results:
    # Так как vulnerability class является типом array извлекаем данные
    vulnerability_classes = result.get('extra', {}).get('metadata', {}).get('vulnerability_class', [])
    # Для читаемости определяем ширину столбца в 60 используя плагин textwrap с помощью вызываемой функции wrap_text
    if vulnerability_classes:
        vulnerability_class = wrap_text(', '.join(vulnerability_classes), 60)
    else:
        "error"
    #vulnerability_class = wrap_text(', '.join(vulnerability_classes), 60) if vulnerability_classes else "error"
    # Повторяем для остальных столбцов
    path = wrap_text(result.get("path", "N/A"), 60)
    cwe_list = result.get('extra', {}).get('metadata', {}).get("cwe", ["N/A"])
    if cwe_list:
        cwe = wrap_text(', '.join(cwe_list), 60)
    else:
        "error"
    #cwe = wrap_text(', '.join(cwe_list), 60) if cwe_list else "N/A"
    impact = wrap_text(result.get('extra', {}).get("severity", "N/A"), 60)
    
    #И наконец добавляем столбцы в таблицу
    table.add_row([vulnerability_class, path, cwe, impact])

# Сортируем по severity
table.sortby = "Severity"
# Выводим в консоль готовую таблицу
print(table)
