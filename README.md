
<p align="center">
[![raw.png](https://i.postimg.cc/VkvCn7PB/raw.png)](https://postimg.cc/bZXrj9Js)
</p>

<h1 align="center">ReconScan</h1>
<p align="center">
  <em>Advanced Web Application Vulnerability Scanner</em><br>
  <strong>Developed for professional red team simulations & security research</strong>
</p>

---

## 🚀 Overview

**ReconScan** is a high-performance, asynchronous web application vulnerability scanner designed for real-world security testing. Built with extensibility, payload precision, and professional-grade reporting in mind, it detects and optionally exploits critical vulnerabilities — all from a clean CLI interface.

This tool is meant for **educational and ethical testing purposes only**, on **systems you own or have explicit permission to audit**.

---

## 🎯 Features

- 🔍 Advanced **SQL Injection** detection (boolean-based, time-based, union-based)
- 💥 **Cross-Site Scripting (XSS)** scanning with DOM/context-specific payloads
- 🧨 **Command Injection** testing and optional **deface payload injection**
- 🔐 **Security Header Analysis** (CSP, X-Frame-Options, etc.)
- 📁 **Path Traversal / LFI** detection
- 🧠 Optional **AI response classification** module
- ⚡ Fully **asynchronous scanning engine** using `aiohttp`
- 🧪 **Unit-tested** with `pytest` for stability
- 📊 Exports reports in **HTML** and **JSON**
- 🖥️ Designed to run cleanly in **Kali Linux** and other security-oriented terminals

---

## 🗂️ Project Structure

```
ReconScan/
├── scanner/           # Core scanning modules
├── config/            # Payloads & settings (YAML)
├── data/              # Wordlists & deface templates
├── reports/           # Output reports (HTML/JSON)
├── scripts/           # CLI entrypoints
├── tests/             # Unit tests
├── models/            # Optional AI/ML models
├── requirements.txt   # Dependencies
├── README.md
└── LICENSE
```

---

## 🛠️ Installation

```bash
git clone https://github.com/YOUR_USERNAME/ReconScan.git
cd ReconScan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📌 Usage

### Basic scan:
```bash
python3 scripts/scan.py --target https://example.com --modules sqli,xss,headers --output reports/scan_result.html
```

### With custom config:
```bash
python3 scripts/scan.py --config config/config.yaml
```

### AI-enhanced response classification:
```bash
python3 scripts/scan.py --target https://testsite.local --ai
```

---

## 🎨 Example Deface Page

ReconScan can optionally trigger **deface payloads** during controlled Command Injection or XSS attacks (e.g., replacing HTML with this styled warning page):

<p align="center">
[![image.png](https://i.postimg.cc/028m2kt4/image.png)](https://postimg.cc/9znzLhHP)
</p>

---

## ⚖️ Legal Disclaimer

> This project is intended for **educational purposes only** and must **only be used in controlled environments** with **explicit permission**.  
> The author does not take responsibility for any misuse of this tool.

---



<p align="center">
  <strong>ReconScan – Scan precisely. Exploit ethically. Report professionally.</strong>
</p>
