import scapy.all as scapy
import csv
from datetime import datetime
import os

LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'packet_log.csv')

def packet_callback(packet):
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
