# WEB MASS SCAN V2.0.0

A high-performance asynchronous web mass scanner for security auditing.

---

## What is WEB MASS SCAN?

`WEB MASS SCAN` is an automated CLI utility built to perform rapid target analysis, web application firewall (WAF) detection, and basic security configuration checks across multiple targets simultaneously using an async multi-threaded engine.

---

## Features

* **Async Multi-Threading Engine:** High-speed network requests.
* **WAF Detection:** Identifies web application firewalls and basic protections.
* **Header Security Check:** Audits missing security headers (CORS, HSTS, CSP).
* **Port Availability Check:** Scans common web/management ports.

---

## Prerequisites

This tool requires **Python 3.8+** and basic network utilities. First run the following command on your terminal:

```bash
apt-get -y install python3 python3-pip git
```

---

## Installing & Usage

### 1. Clone the repository
```bash
git clone [https://github.com/YourUsername/web-mass-scan.git](https://github.com/YourUsername/web-mass-scan.git)
```

### 2. Navigate to directory
```bash
cd web-mass-scan
```

### 3. Install required dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the scanner
```bash
python main.py
```

---

## Clean logs & unnecessary files

To clear generated log files or cached scan results:

```bash
python cleanup.py
```

---

## This Tool Tested On:

* Kali Linux
* Ubuntu
* Parrot Security OS
* Windows (WSL)
* Termux

---

## Disclaimer

> **Notice:** This tool is strictly developed for educational and authorized testing purposes. Always ensure you have authorization before performing any scans on target systems.

A high-performance async web mass scanner for security testing
<img width="706" height="666" alt="Screenshot 2026-07-27 134207" src="https://github.com/user-attachments/assets/0a0e22fc-ef5d-4dfd-a293-a9cfc81c4a43" />
<img width="1844" height="825" alt="Screenshot 2026-07-27 134722" src="https://github.com/user-attachments/assets/a66023a6-761c-4963-91b3-df972a5be15d" />


![Web Mass Scan Banner](images/screenshot1.png)
