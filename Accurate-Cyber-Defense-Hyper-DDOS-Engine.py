import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import random
import socket
import struct
import select
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import pandas as pd
from collections import defaultdict, deque
import ipaddress
import scapy.all as scapy
import psutil
from datetime import datetime
import json
import os
import sys
import subprocess
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Hyper DDOS Engine")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configuration variables
        self.theme = "sky_blue"  # Default theme
        self.traffic_running = False
        self.traffic_thread = None
        self.packets_sent = 0
        self.packets_received = 0
        self.traffic_data = deque(maxlen=100)
        self.protocol_data = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.traffic_by_ip = defaultdict(int)
        self.start_time = time.time()
        
        # Initialize the UI
        self.setup_ui()
        
        # Start background monitoring
        self.monitor_network()
        
    def setup_ui(self):
        # Setup menu bar
        self.setup_menu()
        
        # Setup theme
        self.apply_theme()
        
        # Setup main frames
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        
        # Setup header
        self.setup_header()
        
        # Setup tabs
        self.setup_tabs()
        
        # Setup status bar
        self.setup_status_bar()
    
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.new_scan)
        file_menu.add_command(label="Open Results", command=self.open_results)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Traffic Stats", command=self.show_traffic_stats)
        view_menu.add_command(label="Packet Analysis", command=self.show_packet_analysis)
        view_menu.add_separator()
        
        # Theme submenu
        theme_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Change Theme", menu=theme_menu)
        theme_menu.add_command(label="Sky Blue", command=lambda: self.change_theme("sky_blue"))
        theme_menu.add_command(label="Yellow", command=lambda: self.change_theme("yellow"))
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Packet Sniffer", command=self.open_packet_sniffer)
        tools_menu.add_command(label="Traffic Generator", command=self.open_traffic_generator)
        tools_menu.add_command(label="Network Monitor", command=self.open_network_monitor)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="General", command=self.open_general_settings)
        settings_menu.add_command(label="Network", command=self.open_network_settings)
        settings_menu.add_command(label="Appearance", command=self.open_appearance_settings)
        settings_menu.add_command(label="Notifications", command=self.open_notification_settings)
    
    def setup_header(self):
        header_frame = ttk.Frame(self.main_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(header_frame, text="Accurate Cyber Defense Hyper DDOS Engine", 
                 font=("Arial", 16, "bold")).grid(row=0, column=0, sticky=tk.W)
        
        # Current time label
        self.time_label = ttk.Label(header_frame, text="")
        self.time_label.grid(row=0, column=1, sticky=tk.E)
        self.update_time()
    
    def setup_tabs(self):
        # Create notebook (tab container)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create tabs
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.traffic_tab = ttk.Frame(self.notebook)
        self.analysis_tab = ttk.Frame(self.notebook)
        self.scanner_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        self.notebook.add(self.traffic_tab, text="Traffic Generator")
        self.notebook.add(self.analysis_tab, text="Traffic Analysis")
        self.notebook.add(self.scanner_tab, text="Network Scanner")
        
        # Setup each tab
        self.setup_dashboard_tab()
        self.setup_traffic_tab()
        self.setup_analysis_tab()
        self.setup_scanner_tab()
    
    def setup_dashboard_tab(self):
        # Left frame for stats
        left_frame = ttk.LabelFrame(self.dashboard_tab, text="Network Statistics", padding="10")
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Right frame for charts
        right_frame = ttk.LabelFrame(self.dashboard_tab, text="Traffic Visualization", padding="10")
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Configure grid weights
        self.dashboard_tab.columnconfigure(0, weight=1)
        self.dashboard_tab.columnconfigure(1, weight=1)
        self.dashboard_tab.rowconfigure(0, weight=1)
        
        left_frame.columnconfigure(1, weight=1)
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        
        # Stats labels
        ttk.Label(left_frame, text="Packets Sent:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.sent_label = ttk.Label(left_frame, text="0")
        self.sent_label.grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="Packets Received:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.received_label = ttk.Label(left_frame, text="0")
        self.received_label.grid(row=1, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="TCP Packets:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.tcp_label = ttk.Label(left_frame, text="0")
        self.tcp_label.grid(row=2, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="UDP Packets:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.udp_label = ttk.Label(left_frame, text="0")
        self.udp_label.grid(row=3, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="ICMP Packets:").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.icmp_label = ttk.Label(left_frame, text="0")
        self.icmp_label.grid(row=4, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="Other Packets:").grid(row=5, column=0, sticky=tk.W, pady=2)
        self.other_label = ttk.Label(left_frame, text="0")
        self.other_label.grid(row=5, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="Running Time:").grid(row=6, column=0, sticky=tk.W, pady=2)
        self.time_running_label = ttk.Label(left_frame, text="00:00:00")
        self.time_running_label.grid(row=6, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(left_frame, text="Data Rate:").grid(row=7, column=0, sticky=tk.W, pady=2)
        self.rate_label = ttk.Label(left_frame, text="0 KB/s")
        self.rate_label.grid(row=7, column=1, sticky=tk.W, pady=2)
        
        # Charts
        self.setup_dashboard_charts(right_frame)
    
    def setup_dashboard_charts(self, parent):
        # Create figure for matplotlib
        self.dash_figure = Figure(figsize=(8, 6), dpi=100)
        self.dash_canvas = FigureCanvasTkAgg(self.dash_figure, parent)
        self.dash_canvas.get_tk_widget().grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create subplots
        self.dash_ax1 = self.dash_figure.add_subplot(211)
        self.dash_ax2 = self.dash_figure.add_subplot(212)
        
        # Set initial data
        self.update_dashboard_charts()
    
    def setup_traffic_tab(self):
        # Configuration frame
        config_frame = ttk.LabelFrame(self.traffic_tab, text="Traffic Configuration", padding="10")
        config_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.traffic_tab, text="Traffic Results", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Configure grid weights
        self.traffic_tab.columnconfigure(0, weight=1)
        self.traffic_tab.rowconfigure(1, weight=1)
        
        config_frame.columnconfigure(1, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Target IP
        ttk.Label(config_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_ip = tk.StringVar(value="192.168.1.1")
        ttk.Entry(config_frame, textvariable=self.target_ip).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Port
        ttk.Label(config_frame, text="Target Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.target_port = tk.StringVar(value="80")
        ttk.Entry(config_frame, textvariable=self.target_port).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Packet count
        ttk.Label(config_frame, text="Packet Count:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.packet_count = tk.StringVar(value="1000")
        ttk.Entry(config_frame, textvariable=self.packet_count).grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Packet size
        ttk.Label(config_frame, text="Packet Size (bytes):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.packet_size = tk.StringVar(value="64")
        ttk.Entry(config_frame, textvariable=self.packet_size).grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Protocol
        ttk.Label(config_frame, text="Protocol:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.protocol = tk.StringVar(value="TCP")
        protocol_combo = ttk.Combobox(config_frame, textvariable=self.protocol, state="readonly")
        protocol_combo['values'] = ('TCP', 'UDP', 'ICMP')
        protocol_combo.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Delay
        ttk.Label(config_frame, text="Delay (ms):").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.packet_delay = tk.StringVar(value="10")
        ttk.Entry(config_frame, textvariable=self.packet_delay).grid(row=5, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Button frame
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Traffic", command=self.start_traffic).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Traffic", command=self.stop_traffic).pack(side=tk.LEFT, padx=5)
        
        # Results text area
        self.traffic_results = tk.Text(results_frame, height=15)
        self.traffic_results.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.traffic_results.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.traffic_results['yscrollcommand'] = scrollbar.set
    
    def setup_analysis_tab(self):
        # Create frames
        control_frame = ttk.LabelFrame(self.analysis_tab, text="Analysis Controls", padding="10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), padx=5, pady=5)
        
        chart_frame = ttk.LabelFrame(self.analysis_tab, text="Traffic Analysis", padding="10")
        chart_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Configure grid weights
        self.analysis_tab.columnconfigure(0, weight=1)
        self.analysis_tab.rowconfigure(1, weight=1)
        
        chart_frame.columnconfigure(0, weight=1)
        chart_frame.rowconfigure(1, weight=1)
        
        # Analysis controls
        ttk.Button(control_frame, text="Protocol Distribution", 
                  command=self.show_protocol_chart).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="IP Traffic Distribution", 
                  command=self.show_ip_traffic_chart).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Traffic Over Time", 
                  command=self.show_traffic_time_chart).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Data", 
                  command=self.export_analysis_data).pack(side=tk.LEFT, padx=5)
        
        # Create figure for matplotlib
        self.analysis_figure = Figure(figsize=(10, 8), dpi=100)
        self.analysis_canvas = FigureCanvasTkAgg(self.analysis_figure, chart_frame)
        self.analysis_canvas.get_tk_widget().grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initial empty chart
        self.analysis_ax = self.analysis_figure.add_subplot(111)
        self.analysis_ax.text(0.5, 0.5, 'Select an analysis option to display charts', 
                             horizontalalignment='center', verticalalignment='center', 
                             transform=self.analysis_ax.transAxes, fontsize=14)
        self.analysis_ax.set_xticks([])
        self.analysis_ax.set_yticks([])
        self.analysis_canvas.draw()
    
    def setup_scanner_tab(self):
        # Configuration frame
        config_frame = ttk.LabelFrame(self.scanner_tab, text="Scan Configuration", padding="10")
        config_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), padx=5, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(self.scanner_tab, text="Scan Results", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        
        # Configure grid weights
        self.scanner_tab.columnconfigure(0, weight=1)
        self.scanner_tab.rowconfigure(1, weight=1)
        
        config_frame.columnconfigure(1, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Target IP range
        ttk.Label(config_frame, text="IP Range:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.scan_ip_range = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(config_frame, textvariable=self.scan_ip_range).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Port range
        ttk.Label(config_frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.scan_port_range = tk.StringVar(value="1-1000")
        ttk.Entry(config_frame, textvariable=self.scan_port_range).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Scan type
        ttk.Label(config_frame, text="Scan Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.scan_type = tk.StringVar(value="Quick Scan")
        scan_combo = ttk.Combobox(config_frame, textvariable=self.scan_type, state="readonly")
        scan_combo['values'] = ('Quick Scan', 'Full Scan', 'Port Scan', 'Ping Sweep')
        scan_combo.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Button frame
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        
        # Results text area
        self.scan_results = tk.Text(results_frame, height=15)
        self.scan_results.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.scan_results.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.scan_results['yscrollcommand'] = scrollbar.set
    
    def setup_status_bar(self):
        status_frame = ttk.Frame(self.main_frame)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_label = ttk.Label(status_frame, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X)
        
        ttk.Label(status_frame, text="v1.0", relief=tk.SUNKEN, anchor=tk.E).pack(side=tk.RIGHT, fill=tk.Y)
    
    def apply_theme(self):
        if self.theme == "sky_blue":
            self.root.configure(background='#87CEEB')  # Sky blue
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('.', background='#87CEEB', foreground='black')
            style.configure('TFrame', background='#87CEEB')
            style.configure('TLabel', background='#87CEEB', foreground='black')
            style.configure('TButton', background='#5F9EA0', foreground='black')
            style.configure('TNotebook', background='#87CEEB', borderwidth=0)
            style.configure('TNotebook.Tab', background='#ADD8E6', foreground='black')
            style.map('TNotebook.Tab', background=[('selected', '#5F9EA0')])
            style.configure('TLabelframe', background='#87CEEB', foreground='black')
            style.configure('TLabelframe.Label', background='#87CEEB', foreground='black')
        else:  # yellow theme
            self.root.configure(background='#FFD700')  # Yellow
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('.', background='#FFD700', foreground='black')
            style.configure('TFrame', background='#FFD700')
            style.configure('TLabel', background='#FFD700', foreground='black')
            style.configure('TButton', background='#FFA500', foreground='black')
            style.configure('TNotebook', background='#FFD700', borderwidth=0)
            style.configure('TNotebook.Tab', background='#FFFFE0', foreground='black')
            style.map('TNotebook.Tab', background=[('selected', '#FFA500')])
            style.configure('TLabelframe', background='#FFD700', foreground='black')
            style.configure('TLabelframe.Label', background='#FFD700', foreground='black')
    
    def change_theme(self, theme_name):
        self.theme = theme_name
        self.apply_theme()
    
    def update_time(self):
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def monitor_network(self):
        # Update stats labels
        self.sent_label.config(text=str(self.packets_sent))
        self.received_label.config(text=str(self.packets_received))
        self.tcp_label.config(text=str(self.protocol_data["TCP"]))
        self.udp_label.config(text=str(self.protocol_data["UDP"]))
        self.icmp_label.config(text=str(self.protocol_data["ICMP"]))
        self.other_label.config(text=str(self.protocol_data["Other"]))
        
        # Update running time
        elapsed = time.time() - self.start_time
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.time_running_label.config(text=f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
        
        # Update data rate (simulated)
        if self.traffic_running:
            rate = random.randint(100, 1000)  # Simulated data rate
            self.rate_label.config(text=f"{rate} KB/s")
        
        # Update dashboard charts
        self.update_dashboard_charts()
        
        # Schedule next update
        self.root.after(1000, self.monitor_network)
    
    def update_dashboard_charts(self):
        # Clear previous charts
        self.dash_ax1.clear()
        self.dash_ax2.clear()
        
        # Protocol distribution pie chart
        protocols = list(self.protocol_data.keys())
        counts = list(self.protocol_data.values())
        
        # Filter out protocols with zero counts
        non_zero_indices = [i for i, count in enumerate(counts) if count > 0]
        if non_zero_indices:
            protocols = [protocols[i] for i in non_zero_indices]
            counts = [counts[i] for i in non_zero_indices]
            
            self.dash_ax1.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
            self.dash_ax1.set_title('Protocol Distribution')
        else:
            self.dash_ax1.text(0.5, 0.5, 'No traffic data yet', 
                              horizontalalignment='center', verticalalignment='center', 
                              transform=self.dash_ax1.transAxes)
            self.dash_ax1.set_xticks([])
            self.dash_ax1.set_yticks([])
        
        # Traffic over time (simulated)
        time_points = list(range(1, 11))
        traffic_volume = [random.randint(10, 100) for _ in range(10)]
        
        self.dash_ax2.plot(time_points, traffic_volume, marker='o')
        self.dash_ax2.set_xlabel('Time (seconds)')
        self.dash_ax2.set_ylabel('Traffic Volume (packets)')
        self.dash_ax2.set_title('Traffic Over Time')
        self.dash_ax2.grid(True)
        
        # Adjust layout and draw
        self.dash_figure.tight_layout()
        self.dash_canvas.draw()
    
    def start_traffic(self):
        if self.traffic_running:
            messagebox.showwarning("Warning", "Traffic generation is already running")
            return
        
        # Validate inputs
        try:
            target_ip = self.target_ip.get()
            port = int(self.target_port.get())
            count = int(self.packet_count.get())
            size = int(self.packet_size.get())
            delay = float(self.packet_delay.get()) / 1000  # Convert to seconds
            protocol = self.protocol.get()
            
            # Validate IP address
            try:
                socket.inet_aton(target_ip)
            except socket.error:
                messagebox.showerror("Error", "Invalid IP address")
                return
            
            if port < 1 or port > 65535:
                messagebox.showerror("Error", "Invalid port number")
                return
            
            if count < 1:
                messagebox.showerror("Error", "Packet count must be positive")
                return
            
            if size < 1:
                messagebox.showerror("Error", "Packet size must be positive")
                return
            
            if delay < 0:
                messagebox.showerror("Error", "Delay must be non-negative")
                return
            
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric input")
            return
        
        # Start traffic generation in a separate thread
        self.traffic_running = True
        self.traffic_thread = threading.Thread(
            target=self.generate_traffic,
            args=(target_ip, port, count, size, delay, protocol),
            daemon=True
        )
        self.traffic_thread.start()
        
        self.status_label.config(text=f"Generating {protocol} traffic to {target_ip}:{port}")
        self.traffic_results.insert(tk.END, f"Started {protocol} traffic to {target_ip}:{port}\n")
        self.traffic_results.see(tk.END)
    
    def stop_traffic(self):
        if self.traffic_running:
            self.traffic_running = False
            self.status_label.config(text="Traffic generation stopped")
            self.traffic_results.insert(tk.END, "Traffic generation stopped\n")
            self.traffic_results.see(tk.END)
        else:
            messagebox.showinfo("Info", "No traffic generation is running")
    
    def generate_traffic(self, target_ip, port, count, size, delay, protocol):
        # Simulate traffic generation
        for i in range(count):
            if not self.traffic_running:
                break
                
            # Simulate packet sending
            self.packets_sent += 1
            
            # Update protocol statistics
            self.protocol_data[protocol] += 1
            
            # Update IP traffic statistics
            self.traffic_by_ip[target_ip] += 1
            
            # Add to traffic data for time series
            current_time = time.time()
            self.traffic_data.append((current_time, 1))  # 1 packet at this time
            
            # Simulate some received packets (for demo purposes)
            if random.random() < 0.3:  # 30% chance of receiving a response
                self.packets_received += 1
            
            # Log every 100 packets
            if self.packets_sent % 100 == 0:
                self.traffic_results.insert(tk.END, f"Sent {self.packets_sent} packets to {target_ip}\n")
                self.traffic_results.see(tk.END)
            
            # Delay between packets
            time.sleep(delay)
        
        # Update status when done
        if self.traffic_running:
            self.status_label.config(text=f"Completed sending {count} packets to {target_ip}")
            self.traffic_results.insert(tk.END, f"Completed sending {count} packets to {target_ip}\n")
            self.traffic_results.see(tk.END)
            self.traffic_running = False
    
    def show_protocol_chart(self):
        self.analysis_ax.clear()
        
        protocols = list(self.protocol_data.keys())
        counts = list(self.protocol_data.values())
        
        # Filter out protocols with zero counts
        non_zero_indices = [i for i, count in enumerate(counts) if count > 0]
        if non_zero_indices:
            protocols = [protocols[i] for i in non_zero_indices]
            counts = [counts[i] for i in non_zero_indices]
            
            self.analysis_ax.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90)
            self.analysis_ax.set_title('Protocol Distribution')
        else:
            self.analysis_ax.text(0.5, 0.5, 'No protocol data available', 
                                 horizontalalignment='center', verticalalignment='center', 
                                 transform=self.analysis_ax.transAxes, fontsize=14)
            self.analysis_ax.set_xticks([])
            self.analysis_ax.set_yticks([])
        
        self.analysis_canvas.draw()
    
    def show_ip_traffic_chart(self):
        self.analysis_ax.clear()
        
        if not self.traffic_by_ip:
            self.analysis_ax.text(0.5, 0.5, 'No IP traffic data available', 
                                 horizontalalignment='center', verticalalignment='center', 
                                 transform=self.analysis_ax.transAxes, fontsize=14)
            self.analysis_ax.set_xticks([])
            self.analysis_ax.set_yticks([])
            self.analysis_canvas.draw()
            return
        
        # Get top 10 IPs by traffic
        sorted_ips = sorted(self.traffic_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]
        ips = [ip for ip, count in sorted_ips]
        counts = [count for ip, count in sorted_ips]
        
        # Create bar chart
        y_pos = np.arange(len(ips))
        self.analysis_ax.barh(y_pos, counts, align='center')
        self.analysis_ax.set_yticks(y_pos)
        self.analysis_ax.set_yticklabels(ips)
        self.analysis_ax.invert_yaxis()  # labels read top-to-bottom
        self.analysis_ax.set_xlabel('Packet Count')
        self.analysis_ax.set_title('Traffic by IP Address')
        
        self.analysis_canvas.draw()
    
    def show_traffic_time_chart(self):
        self.analysis_ax.clear()
        
        if not self.traffic_data:
            self.analysis_ax.text(0.5, 0.5, 'No time series data available', 
                                 horizontalalignment='center', verticalalignment='center', 
                                 transform=self.analysis_ax.transAxes, fontsize=14)
            self.analysis_ax.set_xticks([])
            self.analysis_ax.set_yticks([])
            self.analysis_canvas.draw()
            return
        
        # Process time series data (simplified)
        time_points = [t for t, count in self.traffic_data]
        counts = [count for t, count in self.traffic_data]
        
        # Convert to relative time
        if time_points:
            start_time = time_points[0]
            time_points = [t - start_time for t in time_points]
            
            self.analysis_ax.plot(time_points, counts, 'b-')
            self.analysis_ax.set_xlabel('Time (seconds)')
            self.analysis_ax.set_ylabel('Packet Count')
            self.analysis_ax.set_title('Traffic Over Time')
            self.analysis_ax.grid(True)
        else:
            self.analysis_ax.text(0.5, 0.5, 'No time series data available', 
                                 horizontalalignment='center', verticalalignment='center', 
                                 transform=self.analysis_ax.transAxes, fontsize=14)
            self.analysis_ax.set_xticks([])
            self.analysis_ax.set_yticks([])
        
        self.analysis_canvas.draw()
    
    def export_analysis_data(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Create a DataFrame with protocol data
                data = {
                    'Protocol': list(self.protocol_data.keys()),
                    'Count': list(self.protocol_data.values())
                }
                df = pd.DataFrame(data)
                df.to_csv(file_path, index=False)
                
                messagebox.showinfo("Success", f"Data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def start_scan(self):
        ip_range = self.scan_ip_range.get()
        port_range = self.scan_port_range.get()
        scan_type = self.scan_type.get()
        
        self.scan_results.insert(tk.END, f"Starting {scan_type} on {ip_range}\n")
        self.scan_results.see(tk.END)
        
        # Simulate scanning process
        self.simulate_network_scan(ip_range, port_range, scan_type)
    
    def stop_scan(self):
        self.scan_results.insert(tk.END, "Scan stopped by user\n")
        self.scan_results.see(tk.END)
    
    def simulate_network_scan(self, ip_range, port_range, scan_type):
        # This is a simulation of network scanning
        # In a real application, you would use actual scanning techniques
        
        self.scan_results.insert(tk.END, f"Scanning {ip_range} with {scan_type}\n")
        
        # Simulate finding some hosts and open ports
        hosts = [
            ("192.168.1.1", "Router", [80, 443, 22]),
            ("192.168.1.10", "Workstation", [135, 139, 445, 3389]),
            ("192.168.1.15", "Server", [21, 80, 443, 3306]),
            ("192.168.1.20", "Printer", [80, 631]),
        ]
        
        for host, device_type, ports in hosts:
            self.scan_results.insert(tk.END, f"Found host: {host} ({device_type})\n")
            for port in ports:
                self.scan_results.insert(tk.END, f"  Port {port}/tcp open\n")
            self.scan_results.see(tk.END)
            time.sleep(0.5)  # Simulate delay between hosts
        
        self.scan_results.insert(tk.END, "Scan completed\n")
        self.scan_results.see(tk.END)
    
    # Menu command implementations
    def new_scan(self):
        self.scan_results.delete(1.0, tk.END)
        self.status_label.config(text="New scan initialized")
    
    def open_results(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.scan_results.delete(1.0, tk.END)
                    self.scan_results.insert(tk.END, content)
                self.status_label.config(text=f"Loaded results from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file: {str(e)}")
    
    def save_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    content = self.scan_results.get(1.0, tk.END)
                    file.write(content)
                self.status_label.config(text=f"Results saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def show_dashboard(self):
        self.notebook.select(0)
    
    def show_traffic_stats(self):
        self.notebook.select(1)
    
    def show_packet_analysis(self):
        self.notebook.select(2)
    
    def open_port_scanner(self):
        self.notebook.select(3)
        self.status_label.config(text="Port scanner opened")
    
    def open_packet_sniffer(self):
        messagebox.showinfo("Info", "Packet sniffer feature would open here")
        self.status_label.config(text="Packet sniffer opened")
    
    def open_traffic_generator(self):
        self.notebook.select(1)
        self.status_label.config(text="Traffic generator opened")
    
    def open_network_monitor(self):
        messagebox.showinfo("Info", "Network monitor feature would open here")
        self.status_label.config(text="Network monitor opened")
    
    def open_general_settings(self):
        messagebox.showinfo("Info", "General settings would open here")
        self.status_label.config(text="General settings opened")
    
    def open_network_settings(self):
        messagebox.showinfo("Info", "Network settings would open here")
        self.status_label.config(text="Network settings opened")
    
    def open_appearance_settings(self):
        messagebox.showinfo("Info", "Appearance settings would open here")
        self.status_label.config(text="Appearance settings opened")
    
    def open_notification_settings(self):
        messagebox.showinfo("Info", "Notification settings would open here")
        self.status_label.config(text="Notification settings opened")

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()