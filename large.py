from scapy.all import IP, TCP, send
import time

def simulate_large_flow():
    src_ip = "192.168.0.94"  
    dst_ip = "192.168.0.87"
    dst_port = 443  
    payload = "A" * 350
    for i in range (50):
        time.sleep(10)
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=dst_port) / payload
        send(packet)

simulate_large_flow()
