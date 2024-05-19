import tkinter as tk
from tkinter import scrolledtext
import threading
import scapy.all as scapy
from datetime import datetime
from utils.packet_utils import packet_callback

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=150, height=30)
        self.text_area.pack()

        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack()

        self.sniffing = False

