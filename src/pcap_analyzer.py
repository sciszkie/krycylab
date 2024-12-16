from nfstream import NFStreamer
import pandas as pd
from .report import Report
from typing import List
from .alert import Alert
from .ml import ML
from .map import Map
import matplotlib.pyplot as plt

class PcapAnalyzer:
    def __init__(self, normal_pcap_file=None, mal_pcap_file=None, live_interface=None, retrain_norm_pcap=None, retrain_mal_pcap=None) -> None:
        self.report = Report()
        self.map = Map()
        self.normal_stream = None
        self.mal_stream = None
        self.live_interface=live_interface
        self.retrain_norm_stream=None
        self.retrain_mal_stream=None

        if retrain_norm_pcap:
            self.retrain_norm_stream=NFStreamer(source=retrain_norm_pcap, statistical_analysis=True)

        if retrain_mal_pcap:
            self.retrain_mal_stream=NFStreamer(source=retrain_mal_pcap, statistical_analysis=True)

        if normal_pcap_file:
            self.normal_stream = NFStreamer(source=normal_pcap_file, statistical_analysis=True)
        
        if mal_pcap_file:
            self.mal_stream = NFStreamer(source=mal_pcap_file, statistical_analysis=True)
        
        if live_interface:
            self.normal_stream = NFStreamer(source=live_interface, statistical_analysis=True, idle_timeout=1, active_timeout=1 )
            self.mal_stream = NFStreamer(source=live_interface, statistical_analysis=True, idle_timeout=1, active_timeout=1)
        
        self.ml =ML(self.normal_stream,self.mal_stream)

    def build_ml_model(self):
        self.ml.train_and_evaluate_decision_tree()
        print(f"Dokladnosc modelu to:  {self.ml.accuracy}")

    def retrain_ml_model (self):
        self.ml.retrain_model(self.retrain_norm_stream,self.retrain_mal_stream)
        print(f"Dokladnosc modelu to:  {self.ml.accuracy}")
        
    def test_ml_on_new_data (self):
        self.ml.test_model_on_new_data(self.retrain_norm_stream,self.retrain_mal_stream)

    def get_stream_info(self):
        print("jestem tu")
        flow_data_list=[]
        for flow in self.normal_stream:
            print("tu tez")
            flow_data = self.get_flow_data(flow)
            flow_data_list.append(flow_data)
        
        flow_df = pd.DataFrame(flow_data_list)
        
        flow_df.to_json("flows.json", orient="records", lines=True, indent=4)
        
        self.report.stream_info(flow_df)


    def get_flow_data(self,flow):
        flow_data = {
                'id': flow.id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': flow.src_port,
                'dst_port': flow.dst_port,
                'bidirectional_bytes': flow.bidirectional_bytes,
                'bidirectional_packets': flow.bidirectional_packets
            }
        return(flow_data)
    
    def detect_large_flow(self, flow,counter):
        if flow.dst_port == 443 and flow.src2dst_bytes > 300:
            message = f"Suspicious large flow to port 443 from {flow.src_ip}"
            flow_data=self.get_flow_data(flow)
            self.report.create_alert(flow.id, message,flow_data)
            counter+=1
        return counter

    def detect_long_connection(self, flow,counter):
        if flow.bidirectional_duration_ms > 65000:
            message = f"Long connection detected from {flow.src_ip} (duration: {flow.bidirectional_duration_ms} ms)"
            flow_data=self.get_flow_data(flow)
            self.report.create_alert(flow.id, message,flow_data)
            counter+=1
        return(counter)

    def detect_dos_attack(self, flow,counter):
        if flow.bidirectional_packets > 20 and flow.bidirectional_duration_ms < 40000:
            message = f"Potential DoS attack detected from {flow.src_ip} with {flow.bidirectional_packets} packets in {flow.bidirectional_duration_ms} ms"
            flow_data=self.get_flow_data(flow)
            self.report.create_alert(flow.id, message,flow_data)
            counter+=1
        return counter
    
    def detect_blacklisted_ip(self, flow, counter):
        with open("resources/blacklist.txt", 'r') as f:
            blacklist=set(line.strip() for line in f)
        if str(flow.src_ip) in blacklist:
            message = f"Potential attack from suspicious ip: {flow.src_ip}"
            flow_data = self.get_flow_data(flow)
            self.report.create_alert(flow.id, message, flow_data)
            counter += 1
        return counter


    def flow_report(self):
        self.get_stream_info()
        report_json = self.report.to_json()
        with open("report/report.json", "w") as f:
            f.write(report_json)
    
    def machine_learning_classification(self):
        for flow in self.mal_stream:
            flow_data=self.get_flow_data(flow)
            is_malicious=self.ml.ml_find_suspicious_flow(flow)
            if is_malicious:
                message = f"Potential malicious flow from {flow.src_ip} to {flow.dst_ip} with id: {flow.id}."
                flow_data=self.get_flow_data(flow)
                self.report.create_alert(flow.id, message, flow_data)
        suspicious_json = self.report.save_suspicious_flows()
        with open("report/suspicious_report.json", "w") as f:
            f.write(suspicious_json)

    def find_suspicious_flows(self):
        l_f_counter=0
        dos_counter=0
        l_c_counter=0
        for flow in self.mal_stream:
            l_f_counter=self.detect_blacklisted_ip(flow,l_f_counter)
            l_c_counter=self.detect_long_connection(flow,l_c_counter)
            dos_counter=self.detect_dos_attack(flow,dos_counter)
            print (l_c_counter, l_f_counter, dos_counter)
        suspicious_json = self.report.save_suspicious_flows()
        with open("report/suspicious_report.json", "w") as f:
            f.write(suspicious_json)
        self.plot_threat_distribution(l_f_counter, l_c_counter, dos_counter)
        


    def plot_threat_distribution(self, large_flow_count, long_connection_count, dos_count):
        labels = ['Black Listed IP', 'Long Connection', 'DoS Attack']
        sizes = [large_flow_count, long_connection_count, dos_count]

        filtered_labels = [label for label, size in zip(labels, sizes) if size > 0]
        filtered_sizes = [size for size in sizes if size > 0]
        if not filtered_labels:
            print("Brak zagrożeń do wyświetlenia.")
            return
        
        plt.figure(figsize=(10, 5))
        plt.pie(filtered_sizes, labels=filtered_labels, autopct='%1.1f%%', startangle=140)
        plt.title('Distribution of Detected Threats')
        plt.savefig("report/threat_distribution.png")
'''
        
if __name__ == "__main__":
    pcap_analyzer.build_ml_model()
    pcap_analyzer.map.printing_map(pcap_analyzer.normal_stream)
    suspicious_json = pcap_analyzer.report.save_suspicious_flows()
    with open("suspicious_report.json", "w") as f:
        f.write(suspicious_json)
''' 