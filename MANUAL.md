# ReconScan CLI Manual

## 1. Prerequisites
- Python 3.8 or higher
- Linux or MacOS terminal (Python 3.x)
- Virtual environment support (venv module)

## 2. Virtual Environment Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3. Starting the Scanner
### Interactive Mode
```bash
python3 scripts/scan.py
```
At the `ReconScan>` prompt:
```bash
ReconScan> scan <target_url> [options]
```

## 4. scan Command
**Usage:**
```text
scan <target_url> [options]
```
**Description:** Perform web vulnerability scans on the specified target URL.

**Options:**
- `--modules <mod1,mod2,...>`: Modules to run. Available: `sqli`, `xss`, `lfi`, `cmdinjection`, `headers`, `dirtraversal`. Default: `sqli,xss,headers`.
- `--output <file>`: Save results to file (`.json`, `.txt`, `.html`). Default: console.
- `--threads <n>`: Concurrent requests. Default: 5.
- `--timeout <seconds>`: Request timeout. Default: 10.
- `--verbose`: Detailed output.
- `--quiet`: Quiet mode.
- `--dump`: Extract database schema.
- `--dump-tables`: List database tables.
- `--dump-data`: Dump table data.
- `--exploit`: Attempt exploitation.
- `--file-read <path>`: Read file from target.
- `--os-shell`: Open interactive OS shell.
- `--stealth`: Stealth mode.

**Example:**
```bash
python3 scripts/scan.py scan http://testphp.vulnweb.com/listproducts.php?cat=1 --modules sqli --threads 10 --output results.txt
```

## 5. Other CLI Commands
Available at the `ReconScan>` prompt:
- `help [command]` – Show commands or help.
- `run` – Run preset scan profiles with site crawling.
- `config` – View/modify system settings.
- `modules` – List/enable/disable scan modules.
- `payloads` – Display payload templates.
- `deface` – Defacement utilities.
- `exit` – Quit CLI.
- `clear` – Clear screen.

## 6. Examples
### Full Site Crawl with All Modules
```bash
echo "run http://example.com --modules all" | python3 scripts/scan.py
```

### Export JSON Report
```bash
python3 scripts/scan.py scan http://example.com --output report.json
``` 