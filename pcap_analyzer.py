from nfstream import NFStreamer
import pandas as pd
from report import Report
from typing import List
from alert import Alert
from ml import ML
from map import Map

class PcapAnalyzer:
    def __init__(self, normal_pcap_file, mal_pcap_file)-> None:
       self.report = Report()
       self.map=Map()
       self.normal_stream=NFStreamer(source=normal_pcap_file, statistical_analysis = True)
       self.mal_stream=NFStreamer(source=mal_pcap_file, statistical_analysis = True)
       self.ml=self.build_ml_model()

    def build_ml_model(self):
        ml_model=ML(self.normal_stream,self.mal_stream)
        print(ml_model.accuracy)

    def get_stream_info(self):
        flows = self.normal_stream.to_pandas()
        flows.to_json("flows.json", orient="records",lines=False, indent=4)
        data = pd.DataFrame(flows[['id','src_ip','src_mac','src_port','dst_ip','dst_mac', 'dst_port','protocol','bidirectional_bytes']])
        self.report.stream_info(data)


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
    def detect_large_flow(self, flow):
        if flow.dst_port == 443 and flow.src2dst_bytes > 1000:
            message = f"Suspicious large flow to port 443 from {flow.src_ip}"
            flow_data=self.get_flow_data(flow)
            self.report.create_alert(flow.id, message,flow_data)

    def detect_long_connection(self, flow):
        if flow.bidirectional_duration_ms > 300000:
            message = f"Long connection detected from {flow.src_ip} (duration: {flow.bidirectional_duration_ms} ms)"
            flow_data=self.get_flow_data(flow)
            self.report.create_alert(flow.id, message,flow_data)

    def detect_dos_attack(self, flow):
        if flow.bidirectional_packets > 1000 and flow.bidirectional_duration_ms < 10000:
            message = f"Potential DoS attack detected from {flow.src_ip} with {flow.bidirectional_packets} packets in {flow.bidirectional_duration_ms} ms"
            flow_data=self.get_flow_data(flow)
            self.report.create_alert(flow.id, message,flow_data)


if __name__ == "__main__":
    pcap_analyzer = PcapAnalyzer("normal_traffic.pcap","malicious_traffic.pcap")
    pcap_analyzer.get_stream_info()
    for flow in pcap_analyzer.mal_stream:
        pcap_analyzer.detect_large_flow(flow)
        pcap_analyzer.detect_long_connection(flow)
        pcap_analyzer.detect_dos_attack(flow)
    pcap_analyzer.build_ml_model()
    pcap_analyzer.map.printing_map(pcap_analyzer.mal_stream)
    report_json = pcap_analyzer.report.to_json()
    with open("report.json", "w") as f:
        f.write(report_json)
    suspicious_json = pcap_analyzer.report.save_suspicious_flows()
    with open("suspicious_report.json", "w") as f:
        f.write(suspicious_json)
