from src.pcap_analyzer import PcapAnalyzer

def main_menu():
    print("Witamy w systemie analizy sieciowej. Wybierz z listy co chciałbyś zrobić")
    print("1. Analiza plików pcap.")
    print("2. Analiza dynamiczna na interfejsach.")
    print("3. Konfiguracja modelu ML.")
    print("4. Mapa lokalizacji podejrzanych adresów IP.")
    print("5. Wyjście")
    
def analysis_menu():
    print("Wybierz z listy, jakie zadanie chciałbyś zlecić systemowi:")
    print("1. Otrzymanie raportu z danymi wszystkich flow z pcap.")
    print("2. Otrzymanie raportu z podejrzanymi flow + alerty bezpieczeństwa (detection rules).")
    print("3. Otrzymanie raportu z podejrzanymi flow przy użyciu modelu ML.")
    print("4. Cofnij do menu głównego.")
    
def dynamic_analysis_menu():
    print("1. Otrzymanie raportu z analizy pakietów live na interfejsie.")
    print("2. Otrzymanie raportu podejrzanych pakietów live na interfejsie (detection rules).")
    print("3. Otrzymanie raportu podejrzanych pakietów live na interfejsie (ML).")
    print("4. Cofnij do menu głównego.")
    
def ml_config_menu():
    print("Wybierz z listy, jakie zadanie chciałbyś zlecić systemowi:")
    print("1. Wygenerowanie własnego modelu drzewa decyzyjnego do klasyfikacji flow.")
    print("2. Dotrenowanie modelu nowymi danymi.")
    print("3. Przeanalizowanie, jak dobrze obecny model klasyfikuje dane.")
    print("4. Cofnij do menu głównego.")
    
def pcap_analysis():
    option2 = input("Wybieram opcję: ")
    if option2 == "1":
        filename = input("Umieść plik pcap w katalogu resources i podaj jego nazwę: ")
        file = f"resources/{filename}"
        pcap_analyzer = PcapAnalyzer(normal_pcap_file=file)
        pcap_analyzer.flow_report()
        print("Raport został zapisany - jego pełną wersję znajdziesz w katalogu report w pliku report.json.")
        
    elif option2 == "2":
        filename = input("Umieść podejrzany plik pcap w katalogu resources i podaj jego nazwę: ")
        file = f"resources/{filename}"
        pcap_analyzer = PcapAnalyzer(mal_pcap_file=file)
        pcap_analyzer.find_suspicious_flows()
        print("Raport został zapisany - jego pełną wersję znajdziesz w katalogu report w pliku suspicious_report.json.")
        
    elif option2 == "3":
        filename = input("Umieść podejrzany plik pcap w katalogu resources i podaj jego nazwę: ")
        file = f"resources/{filename}"
        pcap_analyzer = PcapAnalyzer(mal_pcap_file=file)
        pcap_analyzer.machine_learning_classification()
        print("Raport został zapisany - jego pełną wersję znajdziesz w katalogu report w pliku suspicious_report.json.")
        
    elif option2 == "4":
        return 
        
    else:
        print("Błąd: Niepoprawna opcja! Spróbuj ponownie.")
        pcap_analysis()

def dynamic_analysis():
    option2 = input("Wybieram opcję: ")
    if option2 == "1":
        interface = input("Podaj nazwę interfejsu: ")
        live_pcap_analyzer = PcapAnalyzer(live_interface=interface)
        live_pcap_analyzer.flow_report()
        print("Analiza rozpoczęta, wciśnij CTRL+C aby zatrzymać.")
        print("Raport został zapisany - jego pełną wersję znajdziesz w katalogu report w pliku suspicious_report.json.")
        
    elif option2 == "2":
        interface = input("Podaj nazwę interfejsu: ")
        live_pcap_analyzer = PcapAnalyzer(live_interface=interface)
        live_pcap_analyzer.find_suspicious_flows()
        print("Analiza rozpoczęta, wciśnij CTRL+C aby zatrzymać.")
        print("Raport został zapisany - jego pełną wersję znajdziesz w katalogu report w pliku suspicious_report.json.")
        
    elif option2 == "3":
        interface = input("Podaj nazwę interfejsu: ")
        live_pcap_analyzer = PcapAnalyzer(live_interface=interface)
        live_pcap_analyzer.machine_learning_classification()
        print("Analiza rozpoczęta, wciśnij CTRL+C aby zatrzymać.")
        print("Raport został zapisany - jego pełną wersję znajdziesz w katalogu report w pliku suspicious_report.json.")
        
    elif option2 == "4":
        return 
        
    else:
        print("Błąd: Niepoprawna opcja! Spróbuj ponownie.")
        dynamic_analysis()

def ml_config():
    option2 = input("Wybieram opcję: ")
    
    if option2 == "1":
        print("Umieść plik pcap o nazwie 'normal_traffic.pcap' z pozytywnymi próbkami w katalogu resources i podaj jego nazwę: ")
        print("Umieść plik pcap o nazwie 'malicious_traffic.pcap' z złośliwymi próbkami w katalogu resources i podaj jego nazwę: ")
        input("Naciśnij Enter, kiedy umieścisz pliki w katalogu resources...")
        try:
            pcap_analyzer = PcapAnalyzer(normal_pcap_file="resources/normal_traffic.pcap", mal_pcap_file="resources/malicious_traffic.pcap")
            pcap_analyzer.build_ml_model()
            print("Model utworzony.")
        except FileNotFoundError:
            print("Błąd: Plik nie znaleziony. Upewnij się, że pliki znajdują się w katalogu 'resources'.")
        except Exception as e:
            print(f"Błąd: {str(e)}")
        
    elif option2 == "2":
        filenamepr = input("Umieść plik pcap z pozytywnymi próbkami w katalogu resources i podaj jego nazwę: ")
        filepr = f"resources/{filenamepr}"
        filenamemr = input("Umieść plik pcap z złośliwymi próbkami w katalogu resources i podaj jego nazwę: ")
        filemr = f"resources/{filenamemr}"
        input("Naciśnij Enter, kiedy umieścisz pliki w katalogu resources...")
        try:
            pcap_analyzer = PcapAnalyzer(normal_pcap_file="resources/normal_traffic.pcap", mal_pcap_file="resources/malicious_traffic.pcap", retrain_norm_pcap=filepr, retrain_mal_pcap=filemr)
            pcap_analyzer.retrain_ml_model()
            print("Model został dotrenowany.")
        except FileNotFoundError:
            print("Błąd: Plik nie znaleziony. Upewnij się, że pliki znajdują się w katalogu 'resources'.")
        except Exception as e:
            print(f"Błąd: {str(e)}")
        
    elif option2 == "3":
        filenamepn = input("Umieść plik pcap z pozytywnymi próbkami w katalogu resources i podaj jego nazwę: ")
        filepn = f"resources/{filenamepn}"
        filenamemn = input("Umieść plik pcap z złośliwymi próbkami w katalogu resources i podaj jego nazwę: ")
        filemn = f"resources/{filenamemn}"
        input("Naciśnij Enter, kiedy umieścisz pliki w katalogu resources...")
        try:
            pcap_analyzer = PcapAnalyzer(normal_pcap_file="resources/normal_traffic.pcap", mal_pcap_file="resources/malicious_traffic.pcap", retrain_norm_pcap=filepn, retrain_mal_pcap=filemn)
            pcap_analyzer.test_ml_on_new_data()
            print("Model przetestowany na nowych danych.")
        except FileNotFoundError:
            print("Błąd: Plik nie znaleziony. Upewnij się, że pliki znajdują się w katalogu 'resources'.")
        except Exception as e:
            print(f"Błąd: {str(e)}")
        
    elif option2 == "4":
        return 
        
    else:
        print("Błąd: Niepoprawna opcja! Spróbuj ponownie.")
        ml_config()

if __name__ == "__main__":
    while True:
        main_menu()
        option = input("Wybieram opcję: ")
        
        if option == "1":
            while True:
                analysis_menu()
                pcap_analysis()
        
        elif option == "2":
            while True:
                dynamic_analysis_menu()
                dynamic_analysis()
        
        elif option == "3":
            while True:
                ml_config_menu()
                ml_config()
        
        elif option == "4":
            file = "resources/normal_traffic.pcap"
            pcap_analyzer = PcapAnalyzer(normal_pcap_file=file)
            pcap_analyzer.map.printing_map(pcap_analyzer.normal_stream)
            print("Mapka wygenerowana.")
        
        elif option == "5":
            print("Do widzenia!")
            break
        
        else:
            print("Błąd: Niepoprawna opcja! Spróbuj ponownie.")
