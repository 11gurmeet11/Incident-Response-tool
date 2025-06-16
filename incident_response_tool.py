#!/usr/bin/env python3
"""
Incident Response Tool – GUI Fast‑Scan Edition
---------------------------------------------
• Recursive directory monitoring via watchdog
• Suspicious‑process polling every 1 s (psutil)
• Remote‑host concurrent port scanning (top 100 TCP ports by default)
• Live Tkinter dashboard with real‑time incident feed
• Export incidents to CSV or PDF (fpdf2)
• Single‑file design, ready for PyInstaller bundling

PyInstaller quick build (create incident_response_tool.exe):
    pyinstaller --onefile --noconsole --add-data "./;." incident_response_tool_gui.py
If watchdog hooks fail to auto‑detect on Windows, add hidden‑imports:
    pyinstaller --onefile --noconsole --hidden-import=watchdog.observers.winapi \
                --hidden-import=watchdog.observers.polling incident_response_tool_gui.py

Required packages:
    pip install psutil watchdog fpdf2

"""

import os
import time
import threading
import queue
import random
import socket
import csv
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import psutil                       # pip install psutil
from watchdog.observers import Observer  # pip install watchdog
from watchdog.events import FileSystemEventHandler

try:
    from fpdf import FPDF           # pip install fpdf2
    _HAS_FPDF = True
except ImportError:
    _HAS_FPDF = False

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ─── CONFIG ─────────────────────────────────────────────────────────────────
SYSTEM_DIR = r"C:\\Windows\\System32"          # Root directory to watch
BLACKLISTED_PROCS = {"ncat", "sqlmap", "wireshark", "powershell"}
PROCESS_POLL_SEC = 1
PORT_SCAN_INTERVAL = 30                       # seconds between auto‑scans
TOP_100_PORTS = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,
    5900,8080,8443,49152,49153,49154,49155,49156,49157,49158,49159,49160,
] + list(range(1024,1044))  # pad to ≈100

LOG_FILE = "incident_log.txt"
CSV_FILE = "incident_log.csv"
PDF_FILE = "incident_log.pdf"

# ─── LOGGING SETUP ─────────────────────────────────────────────────────────
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

def log_event(level: str, msg: str):
    """Write to standard log and GUI queue."""
    timestamped = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {msg}"
    logging.log(logging.WARNING if level != "INFO" else logging.INFO, msg)
    GUI_QUEUE.put(timestamped)

# ─── FILE MONITORING (RECURSIVE) ───────────────────────────────────────────
class RecursiveHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.is_directory:
            return
        log_event("ALERT", f"File modified → {event.src_path}")

class FileWatcher(threading.Thread):
    def __init__(self, path: str):
        super().__init__(daemon=True)
        self.path = path
        self.observer = Observer()

    def run(self):
        handler = RecursiveHandler()
        self.observer.schedule(handler, self.path, recursive=True)
        self.observer.start()
        log_event("INFO", f"Recursive file watch started on {self.path}")
        try:
            while True:
                time.sleep(1)
        except Exception:
            self.observer.stop()
        self.observer.join()

# ─── PROCESS MONITOR ───────────────────────────────────────────────────────
class ProcessWatcher(threading.Thread):
    def run(self):
        log_event("INFO", "Process watcher started")
        while True:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    name = proc.info['name'].lower()
                    if name in BLACKLISTED_PROCS:
                        log_event("ALERT", f"Suspicious process → {name} (PID {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(PROCESS_POLL_SEC)

# ─── PORT SCANNER ──────────────────────────────────────────────────────────
class PortScanner(threading.Thread):
    def __init__(self, host_var: tk.StringVar):
        super().__init__(daemon=True)
        self.host_var = host_var
        self.executor = ThreadPoolExecutor(max_workers=100)

    def scan_ports(self, host: str):
        open_ports = []
        futures = {self.executor.submit(self.check_port, host, p): p for p in TOP_100_PORTS}
        for fut in futures:
            if fut.result():
                open_ports.append(futures[fut])
        if open_ports:
            open_ports.sort()
            log_event("ALERT", f"Open ports on {host} → {', '.join(map(str, open_ports))}")
        else:
            log_event("INFO", f"No top‑100 ports open on {host}")

    @staticmethod
    def check_port(host: str, port: int, timeout: float = 0.3):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def run(self):
        while True:
            host = self.host_var.get() or "127.0.0.1"
            self.scan_ports(host)
            time.sleep(PORT_SCAN_INTERVAL)

# ─── EXPORT FUNCTIONS ──────────────────────────────────────────────────────
def export_csv():
    try:
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "Level", "Message"])
            with open(LOG_FILE, "r", encoding="utf-8") as log:
                for line in log:
                    parts = line.strip().split(" ", 3)
                    if len(parts) >= 4:
                        timestamp = " ".join(parts[0:2])
                        level = parts[2].strip("[]")
                        message = parts[3]
                        writer.writerow([timestamp, level, message])
        messagebox.showinfo("Export CSV", f"Exported to {CSV_FILE}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def export_pdf():
    if not _HAS_FPDF:
        messagebox.showerror("Error", "fpdf2 not installed. Run: pip install fpdf2")
        return
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(0, 10, "Incident Response Report", ln=True)
        pdf.ln(4)
        with open(LOG_FILE, "r", encoding="utf-8") as log:
            for line in log:
                pdf.multi_cell(0, 8, txt=line.strip())
        pdf.output(PDF_FILE)
        messagebox.showinfo("Export PDF", f"Exported to {PDF_FILE}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ─── GUI ───────────────────────────────────────────────────────────────────
class IncidentGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Incident Response Tool – Fast‑Scan Edition")
        self.geometry("800x600")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Host entry for port scanning
        host_frame = ttk.Frame(self)
        host_frame.pack(fill="x", pady=5, padx=5)
        ttk.Label(host_frame, text="Scan Host:").pack(side="left")
        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = ttk.Entry(host_frame, textvariable=self.host_var, width=20)
        host_entry.pack(side="left", padx=5)
        ttk.Button(host_frame, text="Scan Now", command=self.manual_scan).pack(side="left")

        # Log display
        self.log_list = tk.Listbox(self, height=25)
        self.log_list.pack(fill="both", expand=True, padx=5, pady=5)

        # Export buttons
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Export CSV", command=export_csv).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export PDF", command=export_pdf).pack(side="left", padx=5)

        # Start background threads
        FileWatcher(SYSTEM_DIR).start()
        ProcessWatcher().start()
        self.port_scanner = PortScanner(self.host_var)
        self.port_scanner.start()

        self.after(500, self.update_gui)

    def manual_scan(self):
        threading.Thread(target=self.port_scanner.scan_ports, args=(self.host_var.get(),), daemon=True).start()

    def update_gui(self):
        while not GUI_QUEUE.empty():
            msg = GUI_QUEUE.get()
            self.log_list.insert(tk.END, msg)
            self.log_list.yview_moveto(1.0)
        self.after(500, self.update_gui)

    def on_close(self):
        self.destroy()

# ─── GLOBAL QUEUE FOR THREAD‑SAFE LOGS ─────────────────────────────────────
GUI_QUEUE = queue.Queue()

# ─── MAIN ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log_event("INFO", "Incident Response Tool starting…")
    app = IncidentGUI()
    app.mainloop()
