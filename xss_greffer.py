#!/usr/bin/python3
VERSION = 'v2'
import os
import sys
import time
import logging
import urllib3
import requests
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, scrolledtext
from threading import Thread, Lock, Event
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
import uuid
import random
import re
import webbrowser

# User-Agent list for random selection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.65 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; U; Android 4.4.2; en-US; GT-I9505 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/114.0",
]

class XSSGrefferGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("XSS Greffer Scanner")
        self.geometry("800x600")
        self.style = ttk.Style('darkly')
        # Define custom styles for nicer look
        self.style.configure("Main.TFrame", background="#1e1e2e")
        self.style.configure("Summary.TFrame", background="#1e1e2e", relief="solid", borderwidth=1)
        self.style.configure("StatCard.TFrame", background="#1e1e2e", relief="raised", borderwidth=2)
        self.style.configure("Header.TLabel", font=("Roboto Mono", 20, "bold"), foreground="#4fc3f7")
        self.style.configure("SummaryLabel.TLabel", font=("Roboto Mono", 10, "bold"), foreground="#00c853")
        self.style.configure("SummaryValue.TLabel", font=("Roboto Mono", 10), foreground="#b0bec5")
        self.style.configure("Progress.TLabel", font=("Roboto Mono", 10), foreground="#b0bec5")
        self.style.configure("StatValue.TLabel", font=("Roboto Mono", 16, "bold"), foreground="#00c853")
        self.style.configure("StatLabel.TLabel", font=("Roboto Mono", 8), foreground="#b0bec5")
        self.style.configure("VulnTitle.TLabel", font=("Roboto Mono", 14, "bold"), foreground="#4fc3f7")
        self.scan_thread = None
        self.stop_scan = Event()
        self.driver_pool = Queue()
        self.driver_lock = Lock()
        self.vulnerable_urls_lock = Lock()
        self.total_scanned_lock = Lock()
        self.log_lock = Lock()
        self.scan_state = {
            'vulnerability_found': False,
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0,
            'start_time': 0,
            'total_to_scan': 0
        }
        self.scan_running = False
        self.scan_history = []
        self.after_ids = []
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_enabled = False
        self.reports_dir = os.path.join(os.path.dirname(__file__), "xss_greffer_reports")
        self.create_widgets()
        self.load_telegram_config()

    def load_telegram_config(self):
        config_file = os.path.join(os.path.dirname(__file__), "tgbot.txt")
        if not os.path.isfile(config_file):
            self.log("[i] tgbot.txt not found. Telegram notifications disabled.")
            return
        try:
            with open(config_file, "r") as f:
                lines = f.readlines()
                token = None
                chat_id = None
                for line in lines:
                    line = line.strip()
                    if line.startswith("token="):
                        token = line[len("token=["):-1] if line.endswith("]") else line[len("token="):]
                    elif line.startswith("id="):
                        chat_id = line[len("id=["):-1] if line.endswith("]") else line[len("id="):]
                if token and re.match(r'^\d+:[A-Za-z0-9_-]+$', token):
                    self.telegram_token = token
                else:
                    self.log("[!] Invalid Telegram bot token format in tgbot.txt.")
                    return
                if chat_id and re.match(r'^-?\d+$', chat_id):
                    self.telegram_chat_id = chat_id
                else:
                    self.log("[!] Invalid Telegram chat ID format in tgbot.txt.")
                    return
                self.telegram_enabled = True
                self.log("[i] Telegram configuration loaded successfully.")
        except Exception as e:
            self.log(f"[!] Error loading tgbot.txt: {e}. Telegram notifications disabled.")

    def create_widgets(self):
        self.notebook = ttk.Notebook(self, style="TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        self.dashboard_frame = ttk.Frame(self.notebook, padding=15, style="Main.TFrame")
        self.scan_frame = ttk.Frame(self.notebook, padding=15, style="Main.TFrame")
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        self.notebook.add(self.scan_frame, text="Scan")
        self.create_dashboard_widgets()
        self.create_scan_widgets()
        self.notebook.select(self.scan_frame) # Set Scan tab as default

    def create_dashboard_widgets(self):
        container = ttk.Frame(self.dashboard_frame, style="Main.TFrame", padding=20)
        container.pack(fill=tk.BOTH, expand=True)
        container.configure(borderwidth=1, relief="solid")
        ttk.Label(
            container,
            text="XSS Greffer Dashboard",
            style="Header.TLabel",
            anchor="center"
        ).pack(pady=(0, 10))
        # Add Creators' Names
        ttk.Label(
            container,
            text="Created by: Team XSS Greffer",  # Replace with actual names
            font=("Roboto Mono", 10, "italic"),
            foreground="#b0bec5",
            anchor="center"
        ).pack(pady=(0, 10))
        summary_frame = ttk.Frame(container, style="Summary.TFrame", padding=15)
        summary_frame.pack(fill=tk.X, pady=10)
        summary_labels = [
            ("Total Scans:", lambda: str(len(self.scan_history))),
            ("Total Vulnerabilities Found:", lambda: str(self.scan_state['total_found'])),
            ("Total URLs Scanned:", lambda: str(self.scan_state['total_scanned'])),
            ("Elapsed Time:", lambda: f"{int(time.time() - self.scan_state['start_time']) if self.scan_state['start_time'] > 0 else 0}s")
        ]
        for i, (label, value_func) in enumerate(summary_labels):
            ttk.Label(
                summary_frame,
                text=label,
                style="SummaryLabel.TLabel"
            ).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            value_label = ttk.Label(
                summary_frame,
                text=value_func(),
                style="SummaryValue.TLabel"
            )
            value_label.grid(row=i, column=1, sticky="e", padx=5, pady=2)
            ttk.Separator(summary_frame, orient="horizontal").grid(row=i, column=0, columnspan=2, sticky="ew", pady=2)
            setattr(self, f"summary_{label.lower().replace(' ', '_').replace(':', '')}_label", value_label)
        progress_frame = ttk.Frame(container, style="Main.TFrame")
        progress_frame.pack(fill=tk.X, pady=10)
        ttk.Label(progress_frame, text="Scan Progress", style="Progress.TLabel").pack(anchor="w")
        self.progress_canvas = tk.Canvas(progress_frame, height=20, bg="#1e1e2e", highlightthickness=1, highlightbackground="#4fc3f7", relief="sunken")
        self.progress_canvas.pack(fill=tk.X)
        self.progress_bar = self.progress_canvas.create_rectangle(0, 0, 0, 20, fill="#4fc3f7")
        self.progress_width = 0
        def animate_progress():
            if not self.winfo_exists() or not self.scan_running:
                return
            current_width = self.progress_canvas.coords(self.progress_bar)[2]
            canvas_width = self.progress_canvas.winfo_width() or 100
            target_width = (self.scan_state['total_scanned'] / max(self.scan_state['total_to_scan'], 1) * canvas_width)
            if abs(current_width - target_width) > 1:
                self.progress_width += (target_width - current_width) * 0.1
                self.progress_canvas.coords(self.progress_bar, 0, 0, self.progress_width, 20)
            self.progress_canvas.itemconfig(self.progress_bar, fill="#4fc3f7" if random.random() > 0.5 else "#81d4fa")
            after_id = self.after(100, animate_progress)
            self.after_ids.append(after_id)
        after_id = self.after(100, animate_progress)
        self.after_ids.append(after_id)
        stats_grid = ttk.Frame(container, style="Main.TFrame")
        stats_grid.pack(fill=tk.X, pady=10)
        stats_data = [
            ("Vulnerabilities Detected", lambda: str(self.scan_state['total_found'])),
            ("URLs Scanned", lambda: str(self.scan_state['total_scanned'])),
            ("Scan Duration", lambda: f"{int(time.time() - self.scan_state['start_time']) if self.scan_state['start_time'] > 0 else 0}s"),
            ("Vulnerability Rate", lambda: f"{(self.scan_state['total_found'] / self.scan_state['total_scanned'] * 100 if self.scan_state['total_scanned'] > 0 else 0):.2f}%")
        ]
        for i, (label, value_func) in enumerate(stats_data):
            stat_card = ttk.Frame(stats_grid, style="StatCard.TFrame", padding=10)
            stat_card.grid(row=0, column=i, padx=5, sticky="nsew")
            ttk.Label(
                stat_card,
                text=str(value_func()),
                style="StatValue.TLabel",
                anchor="center"
            ).pack()
            ttk.Label(
                stat_card,
                text=label,
                style="StatLabel.TLabel",
                anchor="center"
            ).pack()
            setattr(self, f"stat_{label.lower().replace(' ', '_')}_label", stat_card.winfo_children()[0])
        stats_grid.columnconfigure(tuple(range(len(stats_data))), weight=1)
        vuln_frame = ttk.Frame(container, style="Main.TFrame")
        vuln_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        ttk.Label(
            vuln_frame,
            text="Vulnerable URLs",
            style="VulnTitle.TLabel"
        ).pack(anchor="w")
        scroll_frame = ttk.Frame(vuln_frame)
        scroll_frame.pack(fill=tk.BOTH, expand=True)
        self.vuln_list = tk.Listbox(
            scroll_frame,
            bg="#1e1e2e",
            fg="#4fc3f7",
            font=("Roboto Mono", 10),
            selectbackground="#3a7ca8",
            selectforeground="#ffffff",
            borderwidth=1,
            relief="solid",
            highlightbackground="#4fc3f7",
            highlightthickness=1,
            exportselection=1,
            selectmode="extended"
        )
        self.vuln_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vuln_scroll = ttk.Scrollbar(scroll_frame, orient="vertical", command=self.vuln_list.yview)
        self.vuln_list.config(yscrollcommand=self.vuln_scroll.set)
        self.vuln_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_list.bind("<Double-1>", self.open_vuln_url)
        self.vuln_list.bind("<Control-a>", lambda e: self.select_all_vuln_urls() or "break")
        self.vuln_list.bind("<Control-c>", lambda e: self.copy_vuln_url() or "break")
        self.vuln_list.bind("<Enter>", lambda e: self.vuln_list.config(cursor="hand2"))
        self.vuln_list.bind("<Leave>", lambda e: self.vuln_list.config(cursor=""))
        container.columnconfigure(0, weight=1)
        container.rowconfigure(4, weight=1)

    def create_scan_widgets(self):
        bg_color = "#1e1e2e"
        fg_color = "#b0bec5"
        accent_color = "#4fc3f7"
        button_color = "#00c853"
        main_frame = ttk.Frame(self.scan_frame, style="Main.TFrame", padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(main_frame, text="XSS Greffer Scanner", font=("Roboto Mono", 16, "bold"), foreground=accent_color).pack(pady=10)
       
        ttk.Label(main_frame, text="URLs File or Single URL:", font=("Roboto Mono", 10), foreground=fg_color).pack(anchor="w")
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=5)
        self.url_entry = ttk.Entry(url_frame, width=50, font=("Roboto Mono", 10))
        self.url_entry.pack(side=tk.LEFT, padx=5)
        self.url_entry.bind("<Control-a>", self.select_all)
        ttk.Button(url_frame, text="Browse", command=self.browse_urls, style="success.TButton").pack(side=tk.LEFT)
        ttk.Label(main_frame, text="Payload File:", font=("Roboto Mono", 10), foreground=fg_color).pack(anchor="w")
        payload_frame = ttk.Frame(main_frame)
        payload_frame.pack(fill=tk.X, pady=5)
        self.payload_entry = ttk.Entry(payload_frame, width=50, font=("Roboto Mono", 10))
        self.payload_entry.pack(side=tk.LEFT, padx=5)
        self.payload_entry.bind("<Control-a>", self.select_all)
        ttk.Button(payload_frame, text="Browse", command=self.browse_payloads, style="success.TButton").pack(side=tk.LEFT)
        ttk.Label(main_frame, text="Cookies (e.g., sessionid=abc123; token=xyz789):", font=("Roboto Mono", 10), foreground=fg_color).pack(anchor="w")
        self.cookie_entry = ttk.Entry(main_frame, width=50, font=("Roboto Mono", 10))
        self.cookie_entry.pack(fill=tk.X, pady=5)
        self.cookie_entry.bind("<Control-a>", self.select_all)
        ttk.Label(main_frame, text="Timeout (seconds):", font=("Roboto Mono", 10), foreground=fg_color).pack(anchor="w")
        self.timeout_entry = ttk.Entry(main_frame, width=10, font=("Roboto Mono", 10))
        self.timeout_entry.insert(0, "0.5")
        self.timeout_entry.pack(anchor="w", pady=5)
        self.timeout_entry.bind("<Control-a>", self.select_all)
        ttk.Label(main_frame, text="Threads (1-10):", font=("Roboto Mono", 10), foreground=fg_color).pack(anchor="w")
        self.threads_entry = ttk.Entry(main_frame, width=10, font=("Roboto Mono", 10))
        self.threads_entry.insert(0, "2")
        self.threads_entry.pack(anchor="w", pady=5)
        self.threads_entry.bind("<Control-a>", self.select_all)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan, style="success.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan_action, style="danger.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Report", command=self.generate_report, style="success.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_fields, style="warning.TButton").pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Exit", command=self.exit_application, style="danger.TButton").pack(side=tk.LEFT, padx=5)
        self.output_text = scrolledtext.ScrolledText(main_frame, height=15, font=("Roboto Mono", 10), bg="#121212", fg=fg_color, insertbackground=fg_color)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        self.output_text.bind("<Control-a>", self.select_all_text)
        self.output_text.tag_configure("vulnerable", foreground="#00c853")  # Changed to green
        self.output_text.tag_configure("not_vulnerable", foreground="#ff4444")  # Changed to red
        self.output_text.tag_configure("normal", foreground=fg_color)

    def select_all(self, event):
        event.widget.select_range(0, tk.END)
        event.widget.icursor(tk.END)
        return "break"

    def select_all_text(self, event):
        event.widget.tag_add(tk.SEL, "1.0", tk.END)
        event.widget.mark_set(tk.INSERT, "1.0")
        event.widget.see(tk.INSERT)
        return "break"

    def select_all_vuln_urls(self):
        self.vuln_list.selection_clear(0, tk.END)
        for i in range(self.vuln_list.size()):
            self.vuln_list.selection_set(i)

    def open_vuln_url(self, event):
        try:
            selected = self.vuln_list.get(self.vuln_list.curselection()[0])
            if selected.startswith("http"):
                webbrowser.open(selected)
                self.log(f"[i] Opened URL in browser: {selected}")
        except tk.TclError:
            self.log("[!] No URL selected to open")
            return "break"

    def copy_vuln_url(self):
        try:
            selected = [self.vuln_list.get(i) for i in self.vuln_list.curselection()]
            if selected:
                self.clipboard_clear()
                self.clipboard_append("\n".join(selected))
                self.log(f"[i] URL(s) copied to clipboard: {', '.join(selected)}")
        except tk.TclError:
            self.log("[!] No URL selected to copy")
            return "break"

    def exit_application(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_scan.set()
            self.scan_running = False
            self.log("[i] Stopping running scan before exiting...")
        while not self.driver_pool.empty():
            driver = self.driver_pool.get()
            driver.quit()
        for after_id in self.after_ids:
            self.after_cancel(after_id)
        self.after_ids.clear()
        self.log("[i] Exiting XSS Greffer Scanner.")
        self.destroy()

    def clear_fields(self):
        self.url_entry.delete(0, tk.END)
        self.payload_entry.delete(0, tk.END)
        self.cookie_entry.delete(0, tk.END)
        self.timeout_entry.delete(0, tk.END)
        self.timeout_entry.insert(0, "0.5")
        self.threads_entry.delete(0, tk.END)
        self.threads_entry.insert(0, "2")
        self.output_text.delete(1.0, tk.END)
        with self.vulnerable_urls_lock:
            self.vulnerable_urls = []
            self.scan_state['vulnerable_urls'] = []
            self.scan_state['total_found'] = 0
        with self.total_scanned_lock:
            self.scan_state['total_scanned'] = 0
        self.scan_state['start_time'] = 0
        self.scan_state['total_to_scan'] = 0
        self.scan_state['vulnerability_found'] = False
        self.vuln_list.delete(0, tk.END)
        for after_id in self.after_ids:
            self.after_cancel(after_id)
        self.after_ids.clear()
        self.log("[i] All fields and output cleared.")
        self.update_dashboard()

    def log(self, message):
        with self.log_lock:
            if not self.winfo_exists():
                return
            tag = "normal"
            if "[✓] Vulnerable" in message:
                tag = "vulnerable"
                url_start = message.find(": ") + 2
                url_end = message.find(" - ") if " - " in message else len(message)
                url = message[url_start:url_end]
                if url.startswith("http") and self.telegram_enabled:
                    telegram_message = f"<b>XSS Greffer: Vulnerable URL Found</b>\nURL: {url}\nDetails: {message[url_end:]}"
                    Thread(target=self.send_telegram_notification, args=(telegram_message,)).start()
            elif "[✗] Not Vulnerable" in message:
                tag = "not_vulnerable"
            self.output_text.insert(tk.END, message + "\n", tag)
            self.output_text.see(tk.END)
            self.update_idletasks()

    def browse_urls(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, file_path)

    def browse_payloads(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            self.payload_entry.delete(0, tk.END)
            self.payload_entry.insert(0, file_path)

    def send_telegram_notification(self, message):
        if not self.telegram_enabled or not self.telegram_token or not self.telegram_chat_id:
            return
        api_url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        for attempt in range(3):
            try:
                response = requests.post(api_url, data={
                    "chat_id": self.telegram_chat_id,
                    "text": message,
                    "parse_mode": "HTML"
                }, timeout=5)
                if response.status_code == 200:
                    return
                else:
                    self.log(f"[!] Telegram notification failed (attempt {attempt + 1}/3): {response.text}")
            except Exception as e:
                self.log(f"[!] Telegram notification error (attempt {attempt + 1}/3): {e}")
            time.sleep(1)
        self.log("[!] Telegram notification failed after all retries.")

    def load_payloads(self, payload_file):
        try:
            with open(payload_file, "r") as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            self.log(f"[!] Error loading payloads: {e}")
            return []

    def parse_cookies(self, cookie_string):
        cookies = []
        if not cookie_string:
            self.log("[i] No cookies provided.")
            return cookies
        try:
            parsed_count = 0
            skipped_count = 0
            for cookie in cookie_string.strip().split(';'):
                cookie = cookie.strip()
                if not cookie:
                    skipped_count += 1
                    continue
                if '=' not in cookie:
                    self.log(f"[!] Invalid cookie format skipped: {cookie}")
                    skipped_count += 1
                    continue
                name, value = cookie.split('=', 1)
                name, value = name.strip(), value.strip()
                if not name or not value:
                    self.log(f"[!] Invalid cookie (empty name or value) skipped: {cookie}")
                    skipped_count += 1
                    continue
                cookies.append({'name': name, 'value': value})
                parsed_count += 1
            self.log(f"[i] Parsed {parsed_count} cookies successfully, {skipped_count} skipped.")
            return cookies
        except UnicodeDecodeError as e:
            self.log(f"[!] Unicode error parsing cookies: {e}")
            return []
        except Exception as e:
            self.log(f"[!] Unexpected error parsing cookies: {e}")
            return []

    def generate_payload_urls(self, url, payload):
        url_combinations = []
        scheme, netloc, path, query_string, fragment = urlsplit(url)
        if not scheme:
            scheme = 'http'
        query_params = parse_qs(query_string, keep_blank_values=True)
        for key in query_params.keys():
            modified_params = query_params.copy()
            modified_params[key] = [payload]
            modified_query_string = urlencode(modified_params, doseq=True)
            modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
            url_combinations.append(modified_url)
        return url_combinations

    def create_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-browser-side-navigation")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument("--disable-notifications")
        chrome_options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
        chrome_options.page_load_strategy = 'eager'
        logging.disable(logging.CRITICAL)
        driver_service = ChromeService(ChromeDriverManager().install())
        return webdriver.Chrome(service=driver_service, options=chrome_options)

    def set_cookies(self, driver, url, cookies):
        try:
            scheme, netloc, _, _, _ = urlsplit(url)
            base_url = f"{scheme}://{netloc}"
            driver.get(base_url)
            set_count = 0
            for cookie in cookies:
                try:
                    if 'domain' not in cookie:
                        cookie['domain'] = netloc
                    driver.add_cookie(cookie)
                    set_count += 1
                except webdriver.common.exceptions.InvalidCookieDomainException as e:
                    self.log(f"[!] Failed to set cookie '{cookie['name']}': Invalid domain for {base_url}")
                except Exception as e:
                    self.log(f"[!] Failed to set cookie '{cookie['name']}': {e}")
            cookies_after_set = driver.get_cookies()
            if len(cookies_after_set) >= set_count:
                self.log(f"[✓] Successfully set {set_count} cookies for {base_url}.")
            else:
                self.log(f"[!] Only {len(cookies_after_set)}/{set_count} cookies were set for {base_url}.")
        except webdriver.common.exceptions.WebDriverException as e:
            self.log(f"[!] Error navigating to {base_url}: {e}")
        except Exception as e:
            self.log(f"[!] Unexpected error setting cookies: {e}")

    def get_driver(self):
        try:
            return self.driver_pool.get_nowait()
        except:
            with self.driver_lock:
                return self.create_driver()

    def return_driver(self, driver):
        self.driver_pool.put(driver)

    def update_dashboard(self):
        if not self.winfo_exists():
            return
        self.summary_total_scans_label.config(text=str(len(self.scan_history)))
        self.summary_total_vulnerabilities_found_label.config(text=str(self.scan_state['total_found']))
        self.summary_total_urls_scanned_label.config(text=str(self.scan_state['total_scanned']))
        elapsed_time = int(time.time() - self.scan_state['start_time']) if self.scan_state['start_time'] > 0 else 0
        self.summary_elapsed_time_label.config(text=f"{elapsed_time}s")
        self.stat_vulnerabilities_detected_label.config(text=str(self.scan_state['total_found']))
        self.stat_urls_scanned_label.config(text=str(self.scan_state['total_scanned']))
        self.stat_scan_duration_label.config(text=f"{elapsed_time}s")
        vuln_rate = (self.scan_state['total_found'] / self.scan_state['total_scanned'] * 100) if self.scan_state['total_scanned'] > 0 else 0
        self.stat_vulnerability_rate_label.config(text=f"{vuln_rate:.2f}%")
        self.vuln_list.delete(0, tk.END)
        for url in self.scan_state['vulnerable_urls']:
            self.vuln_list.insert(tk.END, url)
        if self.scan_running:
            after_id = self.after(1000, self.update_dashboard)
            self.after_ids.append(after_id)

    def check_vulnerability(self, url, payload, timeout, cookies):
        if self.stop_scan.is_set():
            return
        driver = self.get_driver()
        try:
            if cookies:
                self.set_cookies(driver, url, cookies)
            payload_urls = self.generate_payload_urls(url, payload)
            if not payload_urls:
                return
            for payload_url in payload_urls:
                if self.stop_scan.is_set():
                    break
                try:
                    driver.get(payload_url)
                    with self.total_scanned_lock:
                        self.scan_state['total_scanned'] += 1
                    self.update_dashboard()
                    try:
                        alert = WebDriverWait(driver, timeout).until(EC.alert_is_present())
                        alert_text = alert.text
                        if alert_text:
                            self.log(f"[✓] Vulnerable: {payload_url} - Alert Text: {alert_text}")
                            with self.vulnerable_urls_lock:
                                self.vulnerable_urls.append(payload_url)
                                self.scan_state['vulnerable_urls'].append(payload_url)
                                self.scan_state['total_found'] += 1
                                self.scan_state['vulnerability_found'] = True
                            alert.accept()
                        else:
                            self.log(f"[✗] Not Vulnerable: {payload_url}")
                    except TimeoutException:
                        self.log(f"[✗] Not Vulnerable: {payload_url}")
                    except UnexpectedAlertPresentException as e:
                        try:
                            alert = driver.switch_to.alert
                            alert_text = alert.text
                            self.log(f"[✓] Vulnerable: {payload_url} - Alert Text: {alert_text}")
                            with self.vulnerable_urls_lock:
                                self.vulnerable_urls.append(payload_url)
                                self.scan_state['vulnerable_urls'].append(payload_url)
                                self.scan_state['total_found'] += 1
                                self.scan_state['vulnerability_found'] = True
                            alert.accept()
                        except:
                            self.log(f"[!] Failed to handle unexpected alert: {e}")
                except Exception as e:
                    self.log(f"[!] Error testing URL {payload_url}: {e}")
        finally:
            self.return_driver(driver)

    def run_scan(self, urls, payload_file, timeout, cookies, threads):
        self.payloads = self.load_payloads(payload_file)
        if not self.payloads:
            messagebox.showerror("Error", "No payloads loaded. Please check the payload file.")
            return
        self.scan_running = True
        self.scan_history.append({
            'urls': urls,
            'payload_file': payload_file,
            'timestamp': time.time()
        })
        self.scan_state['total_to_scan'] = len(urls) * len(self.payloads)
        with self.vulnerable_urls_lock:
            self.vulnerable_urls = []
            self.scan_state['vulnerable_urls'] = []
            self.scan_state['total_found'] = 0
        with self.total_scanned_lock:
            self.scan_state['total_scanned'] = 0
        self.scan_state['start_time'] = time.time()
        self.scan_state['vulnerability_found'] = False
        driver_count = min(threads, 4)
        for _ in range(driver_count):
            self.driver_pool.put(self.create_driver())
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for url in urls:
                    if self.stop_scan.is_set():
                        break
                    self.log(f"→ Scanning URL: {url}")
                    for payload in self.payloads:
                        if self.stop_scan.is_set():
                            break
                        futures.append(
                            executor.submit(self.check_vulnerability, url, payload, timeout, cookies)
                        )
                for future in as_completed(futures):
                    if self.stop_scan.is_set():
                        executor._threads.clear()
                        break
                    try:
                        future.result()
                    except Exception as e:
                        self.log(f"[!] Error during scan: {e}")
        finally:
            while not self.driver_pool.empty():
                driver = self.driver_pool.get()
                driver.quit()
            self.scan_running = False
            for after_id in self.after_ids:
                self.after_cancel(after_id)
            self.after_ids.clear()
            elapsed_time = int(time.time() - self.scan_state['start_time'])
            self.log(f"→ Scanning finished.")
            self.log(f"• Total found: {self.scan_state['total_found']}")
            self.log(f"• Total scanned: {self.scan_state['total_scanned']}")
            self.log(f"• Time taken: {elapsed_time} seconds")
            self.update_dashboard()
            # Automatically save HTML report
            if self.scan_state['total_scanned'] > 0:
                timestamp = time.strftime("%Y-%m-%d_%H-%M")
                os.makedirs(self.reports_dir, exist_ok=True)
                report_filename = os.path.join(self.reports_dir, f"xss_greffer_report_{timestamp}.html")
                html_content = self.generate_html_report(
                    "Cross-Site Scripting (XSS)",
                    self.scan_state['total_found'],
                    self.scan_state['total_scanned'],
                    elapsed_time,
                    self.scan_state['vulnerable_urls']
                )
                try:
                    with open(report_filename, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    self.log(f"[✓] HTML report automatically saved as {report_filename}")
                    if self.telegram_enabled:
                        Thread(target=self.send_telegram_notification, args=(f"<b>XSS Greffer: Report Generated</b>\nReport saved as {report_filename}",)).start()
                except Exception as e:
                    self.log(f"[✗] Failed to save automatic HTML report: {e}")
            if self.telegram_enabled:
                summary = (
                    f"<b>XSS Greffer: Scan Completed</b>\n"
                    f"Total URLs Scanned: {self.scan_state['total_scanned']}\n"
                    f"Vulnerabilities Found: {self.scan_state['total_found']}\n"
                    f"Time Taken: {elapsed_time} seconds"
                )
                Thread(target=self.send_telegram_notification, args=(summary,)).start()

    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Warning", "A scan is already running!")
            return
        url_input = self.url_entry.get().strip()
        payload_file = self.payload_entry.get().strip()
        timeout_str = self.timeout_entry.get().strip()
        cookie_string = self.cookie_entry.get().strip()
        threads_str = self.threads_entry.get().strip()
        if not url_input or not payload_file:
            messagebox.showerror("Error", "Please provide a URLs file or a single URL and a payload file.")
            return
        if not os.path.isfile(payload_file):
            messagebox.showerror("Error", "Payload file does not exist.")
            return
        try:
            timeout = float(timeout_str) if timeout_str else 0.5
        except ValueError:
            messagebox.showerror("Error", "Invalid timeout value. Using default 0.5 seconds.")
            timeout = 0.5
        try:
            threads = int(threads_str) if threads_str and threads_str.isdigit() and 1 <= int(threads_str) <= 10 else 2
        except ValueError:
            messagebox.showerror("Error", "Invalid thread count. Using default 2 threads.")
            threads = 2
        cookies = self.parse_cookies(cookie_string)
        if os.path.isfile(url_input):
            try:
                with open(url_input) as file:
                    urls = [line.strip() for line in file if line.strip()]
            except Exception as e:
                messagebox.showerror("Error", f"Error reading URLs file: {e}")
                return
        else:
            if url_input:
                urls = [url_input]
            else:
                messagebox.showerror("Error", "Please provide a valid URLs file or a single URL.")
                return
        self.stop_scan.clear()
        self.output_text.delete(1.0, tk.END)
        self.log("[i] Starting scan...")
        self.log(f"[i] Using {threads} threads for scanning.")
        if self.telegram_enabled:
            Thread(target=self.send_telegram_notification, args=(f"<b>XSS Greffer: Scan Starting</b>\nUsing {threads} threads",)).start()
        self.scan_thread = Thread(target=self.run_scan, args=(urls, payload_file, timeout, cookies, threads))
        self.scan_thread.start()

    def stop_scan_action(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_scan.set()
            self.scan_running = False
            self.log("[!] Scan interrupted by the user.")
            for after_id in self.after_ids:
                self.after_cancel(after_id)
            self.after_ids.clear()
            if self.scan_state['total_scanned'] > 0:
                timestamp = time.strftime("%Y-%m-%d_%H-%M")
                os.makedirs(self.reports_dir, exist_ok=True)
                report_filename = os.path.join(self.reports_dir, f"xss_greffer_report_{timestamp}.html")
                html_content = self.generate_html_report(
                    "Cross-Site Scripting (XSS)",
                    self.scan_state['total_found'],
                    self.scan_state['total_scanned'],
                    int(time.time() - self.scan_state['start_time']),
                    self.scan_state['vulnerable_urls']
                )
                try:
                    with open(report_filename, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    self.log(f"[✓] HTML report automatically saved as {report_filename}")
                    if self.telegram_enabled:
                        Thread(target=self.send_telegram_notification, args=(f"<b>XSS Greffer: Report Generated</b>\nReport saved as {report_filename}",)).start()
                except Exception as e:
                    self.log(f"[✗] Failed to save automatic HTML report: {e}")
            if self.telegram_enabled:
                Thread(target=self.send_telegram_notification, args=("<b>XSS Greffer: Scan Stopped</b>\nScan was interrupted by the user.",)).start()
        else:
            messagebox.showinfo("Info", "No scan is currently running.")
        self.update_dashboard()

    def generate_html_report(self, scan_type, total_found, total_scanned, time_taken, vulnerable_urls):
        vuln_rate = (total_found / total_scanned * 100) if total_scanned > 0 else 0
        total_scans = len(self.scan_history)
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>XSS Greffer Scan Report</title>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap');
                :root {{
                    --primary-color: #b0bec5;
                    --secondary-color: #4fc3f7;
                    --accent-color: #00c853;
                    --background-color: #121212;
                    --container-bg: #1e1e2e;
                    --glow-color: rgba(79, 195, 247, 0.5);
                }}
                body {{
                    font-family: 'Roboto Mono', monospace;
                    line-height: 1.6;
                    color: var(--primary-color);
                    background-color: var(--background-color);
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 900px;
                    margin: 2rem auto;
                    padding: 2rem;
                    background-color: var(--container-bg);
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
                    border-radius: 8px;
                    border: 1px solid var(--secondary-color);
                }}
                .animated-text {{
                    font-size: 2rem;
                    font-weight: bold;
                    color: var(--secondary-color);
                    text-shadow: 0 0 5px var(--secondary-color);
                    margin-bottom: 1rem;
                    text-align: center;
                }}
                .creators {{
                    font-size: 1rem;
                    font-style: italic;
                    color: var(--primary-color);
                    text-align: center;
                    margin-bottom: 1rem;
                }}
                .summary {{
                    background-color: var(--container-bg);
                    padding: 1.5rem;
                    border-radius: 8px;
                    margin-bottom: 2rem;
                    border: 1px solid var(--secondary-color);
                }}
                .summary-item {{
                    display: flex;
                    justify-content: space-between;
                    margin-bottom: 0.5rem;
                    border-bottom: 1px solid rgba(79, 195, 247, 0.3);
                }}
                .summary-label {{
                    font-weight: bold;
                    color: var(--accent-color);
                }}
                .summary-value {{
                    color: var(--primary-color);
                }}
                .progress-bar {{
                    width: 100%;
                    height: 20px;
                    background-color: rgba(79, 195, 247, 0.1);
                    border-radius: 10px;
                    overflow: hidden;
                    margin-bottom: 1rem;
                }}
                .progress {{
                    width: {vuln_rate:.2f}%;
                    height: 100%;
                    background-color: var(--secondary-color);
                    transition: width 0.3s ease;
                }}
                .stats-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 1rem;
                    margin-bottom: 2rem;
                }}
                .stat-card {{
                    background-color: var(--container-bg);
                    padding: 1rem;
                    border-radius: 8px;
                    text-align: center;
                    border: 1px solid var(--secondary-color);
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                }}
                .stat-card:hover {{
                    transform: scale(1.02);
                    box-shadow: 0 0 10px var(--glow-color);
                }}
                .stat-value {{
                    font-size: 1.8rem;
                    font-weight: bold;
                    color: var(--accent-color);
                }}
                .stat-label {{
                    font-size: 0.9rem;
                    color: var(--primary-color);
                }}
                .vulnerable-item {{
                    background-color: rgba(79, 195, 247, 0.1);
                    border: 1px solid var(--secondary-color);
                    color: var(--secondary-color);
                    padding: 1rem;
                    margin-bottom: 1rem;
                    border-radius: 4px;
                    word-break: break-all;
                    transition: transform 0.2s ease, box-shadow 0.2s ease;
                }}
                .vulnerable-item:hover {{
                    transform: scale(1.02);
                    box-shadow: 0 0 10px var(--glow-color);
                }}
                .vulnerable-item a {{
                    color: var(--secondary-color);
                    text-decoration: none;
                }}
                .vulnerable-item a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="animated-text">XSS Greffer Scan Report</h1>
                <div class="creators">Created by: Team XSS Greffer</div>
                <div class="summary">
                    <div class="summary-item">
                        <span class="summary-label">Total Scans:</span>
                        <span class="summary-value">{total_scans}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Total Vulnerabilities Found:</span>
                        <span class="summary-value">{total_found}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Total URLs Scanned:</span>
                        <span class="summary-value">{total_scanned}</span>
                    </div>
                    <div class="summary-item">
                        <span class="summary-label">Time Taken:</span>
                        <span class="summary-value">{time_taken} seconds</span>
                    </div>
                </div>
                <div class="progress-bar">
                    <div class="progress"></div>
                </div>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{total_found}</div>
                        <div class="stat-label">Vulnerabilities Detected</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{total_scanned}</div>
                        <div class="stat-label">URLs Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{time_taken}s</div>
                        <div class="stat-label">Scan Duration</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{vuln_rate:.2f}%</div>
                        <div class="stat-label">Vulnerability Rate</div>
                    </div>
                </div>
                <h2 class="animated-text">Vulnerable URLs</h2>
                <ul class="vulnerable-list">
                    {"".join(f'<li class="vulnerable-item"><a href="{url}" target="_blank">{url}</a></li>' for url in vulnerable_urls)}
                </ul>
            </div>
        </body>
        </html>
        """
        return html_content

    def generate_report(self):
        if not self.scan_state['vulnerable_urls'] and self.scan_state['total_found'] == 0:
            messagebox.showwarning("Warning", "No scan results available. Please run a scan first.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html"), ("All files", "*.*")])
        if not filename:
            self.log("[i] Report generation cancelled.")
            return
        html_content = self.generate_html_report(
            "Cross-Site Scripting (XSS)",
            self.scan_state['total_found'],
            self.scan_state['total_scanned'],
            int(time.time() - self.scan_state['start_time']) if self.scan_state['start_time'] else 0,
            self.scan_state['vulnerable_urls']
        )
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.log(f"[✓] HTML report saved as {filename}")
            messagebox.showinfo("Success", f"HTML report saved as {filename}")
            if self.telegram_enabled:
                Thread(target=self.send_telegram_notification, args=(f"<b>XSS Greffer: Report Generated</b>\nReport saved as {filename}",)).start()
        except Exception as e:
            self.log(f"[✗] Failed to save HTML report: {e}")
            messagebox.showerror("Error", f"Failed to save HTML report: {e}")

    def __del__(self):
        while not self.driver_pool.empty():
            driver = self.driver_pool.get()
            driver.quit()
        for after_id in self.after_ids:
            self.after_cancel(after_id)

def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.getLogger('WDM').setLevel(logging.ERROR)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    app = XSSGrefferGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
