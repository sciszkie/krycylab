from src.pcap_analyzer import PcapAnalyzer


if __name__ == "__main__":
    pcap_analyzer = PcapAnalyzer(normal_pcap_file="resources/normal_traffic.pcap",mal_pcap_file="resources/malicious_traffic.pcap")
    print ("Witamy w systemie analizy plików pcap. Wybierz z listy co chciałbys zrobic")
    print("1. Otrzymanie raportu z danymi wszystkich flow z pcap .")
    print("2. Otrzymanie raportu z podejrzanymi flow + alerty bezpieczeństwa.")
    print("3. Wygeneruj model drzewa decyzyjnego do klasyfikacji flow.")
    print("4. Mapa lokalizacji podejrzanych adresów IP.")
    print("5. Rozpocznij zbieranie pakietów live.")
    print("6. Znajdź złośliwy ruch przy użyciu modelu ML.")
    print ("7. Włącz analizę ruchu na bazie modelu ml (live).")
    print ("8. Dotrenuj model nowymi danymi.")
    print("9. Rozpocznij analizę live pakietów na interfejsie (detection rules).")
    print ("10. Zobacz jak dobrze obecny model klasyfikuje dane.")
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
    elif (option=='6'):
        machine_learning_pcap=PcapAnalyzer(mal_pcap_file="resources/mixed_traffic.pcap")
        machine_learning_pcap.machine_learning_classification()
        print ("Ruch zostal oceniony")
    elif (option=='7'):
        live_pcap_analyzer=PcapAnalyzer(live_interface="enp0s3")
        live_pcap_analyzer.machine_learning_classification()
    elif (option=='8'):
        pcap_analyzer_retrain = PcapAnalyzer(normal_pcap_file="resources/normal_traffic.pcap",mal_pcap_file="resources/malicious_traffic.pcap",retrain_norm_pcap="resources/retrain_norm.pcap",retrain_mal_pcap="resources/retrain_mal.pcap")
        pcap_analyzer_retrain.retrain_ml_model()
    elif (option=='9'):
        live_pcap_analyzer=PcapAnalyzer(live_interface="enp0s3")
        live_pcap_analyzer.find_suspicious_flows()
    elif (option=='10'):
        pcap_analyzer_retrain = PcapAnalyzer(normal_pcap_file="resources/normal_traffic.pcap",mal_pcap_file="resources/malicious_traffic.pcap",retrain_norm_pcap="resources/retrain_norm.pcap",retrain_mal_pcap="resources/retrain_mal.pcap")
        pcap_analyzer_retrain.test_ml_on_new_data()