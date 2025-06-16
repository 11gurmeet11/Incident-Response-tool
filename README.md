# 🛡️ Incident Response Tool – Fast‑Scan GUI

---

A real-time incident response tool built in Python with a modern Tkinter dashboard interface. This tool monitors system changes, scans for suspicious processes, performs remote port scanning, and exports detailed incident reports — all from a single script.

---
🔒 Ethical Use
---
This tool is intended strictly for educational and authorized use only.
Do not use on networks/systems you do not own or have explicit permission to analyze.


---

## 🚀 Features

- 🔁 **Recursive Directory Monitoring**  
  Watches system folders (e.g., `C:\Windows\System32`) in real-time using `watchdog`.

- 🧠 **Suspicious Process Detection**  
  Monitors all running processes every 1 second and flags blacklisted ones like `sqlmap`, `ncat`, etc.

- 🌐 **Remote Port Scanner**  
  Concurrently scans top 100 TCP ports of a given IP/domain. Supports manual and scheduled scans.

- 📊 **Live Tkinter Dashboard**  
  - Incident feed
  - On-demand port scan
  - Export buttons (CSV, PDF)

- 📤 **Exportable Reports**  
  - Export incidents to `incident_log.csv` or `incident_log.pdf` using `fpdf2`.

- 🧾 **Log File**  
  - All events saved in `incident_log.txt`.

---
Tested on:
---
✅ Windows 10/11
✅ Python 3.9+

---

## 🛠️ Requirements

```bash
pip install psutil watchdog fpdf2
