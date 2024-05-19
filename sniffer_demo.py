import socket
import struct
import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, str_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet frame:')
        print('Destination: {}, Source: {}, Protocol: {}.format(dest_mac, src_mac, eth_proto))
              
def ethernnet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]

def get_mac_addr(bytes_addr):
    bytes_str = map('{02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

#unpack IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4 #bit shift it by 4 to the right
    header_length = (version_header_length & 15) * 4 #compare 2 bytes
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return  '.'.join(map(str, addr)) # converting to string 127.0.0.1 for example

# unpack ICMP internet control message protocol packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]
