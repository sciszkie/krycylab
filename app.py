from pcap_analyzer import PcapAnalyzer


if __name__ == "__main__":
    pcap_analyzer = PcapAnalyzer(normal_pcap_file="normal_traffic.pcap",mal_pcap_file="malicious_traffic.pcap")
    print ("Witamy w systemie analizy plików pcap. Wybierz z listy co chciałbys zrobic")
    print("1. Otrzymanie raportu z danymi wszystkich flow z pcap .")
    print("2. Otrzymanie raportu z podejrzanymi flow + alerty bezpieczeństwa.")
    print("3. Model drzewa decyzyjnego do klasyfikacji flow")
    print("4. Mapa loalizacji podejrzanych adresów IP.")
    option = input("Wybieram opcje: ")
    if (option=="1"):
        pcap_analyzer.flow_report()
        print ("Raport został zapisany")
    elif (option=="2"):
        pcap_analyzer.find_suspicious_flows()
        print("Raport podejrzanych flow zapisany")
    elif (option=="3"):
        pcap_analyzer.build_ml_model()
        print("Model utworzony")
    elif(option=="4"):
        pcap_analyzer.map.printing_map(pcap_analyzer.normal_stream)
        print ("Mapka wygenerowana")
    elif (option=='5'):
        live_pcap_analyzer=PcapAnalyzer(live_interface="enp0s3")
        live_pcap_analyzer.flow_report()