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

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        scapy.sniff(prn=self.display_packet, store=0, stop_filter=lambda x: not self.sniffing)
