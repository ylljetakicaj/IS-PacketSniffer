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
            
        # TCP details
        if scapy.TCP in packet:
            tcp_sport = packet[scapy.TCP].sport
            tcp_dport = packet[scapy.TCP].dport
            tcp_seq = packet[scapy.TCP].seq
            tcp_flags = packet[scapy.TCP].flags
        else:
            tcp_sport = tcp_dport = tcp_seq = tcp_flags = None
        
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        
        with open(LOG_FILE, 'a', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([
                timestamp, eth_src, eth_dst, eth_proto,
                ip_src, ip_dst, ip_proto, ip_version, ip_ihl, ip_ttl,
                tcp_sport, tcp_dport, tcp_seq, tcp_flags
            ])
        
        log_message = (
            f"{timestamp} - Ethernet: {eth_src} -> {eth_dst} [Protocol: {eth_proto}], "
            f"IPv4: {ip_src} -> {ip_dst} [Protocol: {ip_proto}, Version: {ip_version}, "
            f"Header Length: {ip_ihl}, TTL: {ip_ttl}], "
            f"TCP: {tcp_sport} -> {tcp_dport} [Seq: {tcp_seq}, Flags: {tcp_flags}]"
        )
        print(log_message)

def start_sniffer():
    print("Starting packet sniffer...")
    scapy.sniff(prn=packet_callback, store=0)
