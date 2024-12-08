from nfstream import NFStreamer
import pandas as pd
from report import Report
from typing import List
from alert import Alert

class PcapAnalyzer:
    def __init__(self, pcap_file)-> None:
       self.report = Report()
       self.stream=NFStreamer(source=pcap_file, statistical_analysis = True)

    def get_stream_info(self):
        flows = self.stream.to_pandas()
        data = pd.DataFrame(flows[['id','src_ip','src_mac','src_port','dst_ip','dst_mac', 'dst_port','protocol','bidirectional_bytes']])
        self.report.stream_info(data)

    def detect_large_flow(self, flow):
        if flow.dst_port == 443 and flow.src2dst_bytes > 1000:
            self.report.create_alert(flow.id, flow.src_ip)

if __name__ == "__main__":
    pcap_analyzer = PcapAnalyzer("normal_traffic.pcap")
    pcap_analyzer.get_stream_info()
    for flow in pcap_analyzer.stream:
        pcap_analyzer.detect_large_flow(flow)
    report_json = pcap_analyzer.report.to_json()
    print(report_json)
    with open("report.json", "w") as f:
        f.write(report_json)
