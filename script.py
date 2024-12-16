from scapy.all import IP, TCP, send
import time
# Tworzymy pakiet IP z ICMP
packet = IP(src="192.168.0.3", dst="192.168.0.87") / TCP(sport=12345, dport=80, flags="S")  # Flaga SYN (do rozpoczęcia połączenia)

# Wysyłamy pakiet
send(packet)



# Wysyłamy pakiet co 5 sekund (symulacja ruchu)
for i in range(10):  # Wysłać 10 pakietów
    time.sleep(5)  # Czekamy 5 sekund pomiędzy wysłaniem pakietów
    send(packet)    # Wysyłamy pakiet do portu 443 na serwerze docelowym
