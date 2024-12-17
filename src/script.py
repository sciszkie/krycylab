from scapy.all import IP, TCP, send
import time
packet = IP(src="192.168.0.3", dst="192.168.0.87") / TCP(sport=12345, dport=80, flags="S")  # Flaga SYN (do rozpoczęcia połączenia)

send(packet)



for i in range(10):
    time.sleep(5)
    send(packet)
