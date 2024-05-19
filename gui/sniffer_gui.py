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

    def display_packet(self, packet):
        if scapy.Ether in packet:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Ethernet details
            eth_src = packet[scapy.Ether].src
            eth_dst = packet[scapy.Ether].dst
            eth_proto = packet[scapy.Ether].type
            
            # IPv4 details
            if scapy.IP in packet:
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst
                ip_proto = packet[scapy.IP].proto
                ip_version = packet[scapy.IP].version
                ip_ihl = packet[scapy.IP].ihl
                ip_ttl = packet[scapy.IP].ttl
            else:
                ip_src = ip_dst = ip_proto = ip_version = ip_ihl = ip_ttl = None
            
            # TCP details
            if scapy.TCP in packet:
                tcp_sport = packet[scapy.TCP].sport
                tcp_dport = packet[scapy.TCP].dport
                tcp_seq = packet[scapy.TCP].seq
                tcp_flags = packet[scapy.TCP].flags
            else:
                tcp_sport = tcp_dport = tcp_seq = tcp_flags = None
            
            log_message = (
                f"{timestamp} - Ethernet: {eth_src} -> {eth_dst} [Protocol: {eth_proto}], "
                f"IPv4: {ip_src} -> {ip_dst} [Protocol: {ip_proto}, Version: {ip_version}, "
                f"Header Length: {ip_ihl}, TTL: {ip_ttl}], "
                f"TCP: {tcp_sport} -> {tcp_dport} [Seq: {tcp_seq}, Flags: {tcp_flags}]\n"
            )
            self.text_area.insert(tk.END, log_message)
            self.text_area.yview(tk.END)
            packet_callback(packet)  # Log to file as well

def start_gui():
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()
