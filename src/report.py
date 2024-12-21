import json
from typing import List,Dict
from uuid import uuid4
from .alert import Alert
from nfstream import NFStreamer
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib

matplotlib.use('TkAgg')

class Report:
    def __init__(self) -> None:
        self.report_id: str = str(uuid4())
        self.data = []
        self.generated_alerts: Dict[str, List[Alert]] = {}
        self.suspicious_flows=[]
        self.ip_communication_count = {}

    def create_alert(self, flow_id ,message,flow_data):
        alert = Alert(flow_id, message)
        if flow_id not in self.generated_alerts:
            self.generated_alerts[flow_id] = []
        self.generated_alerts[flow_id].append(alert)
        self.suspicious_flows.append(flow_data)

    def stream_info(self, data):
        data_json = data.to_dict(orient='records')
        self.data = data_json

    def to_json(self):
        report = {
            "report_id": self.report_id,
            "section 1": "Flows data" ,
            "flows": self.data,
            "section 2": "IP Communications Count",
            "ip_communications": self.ip_communication_count,
        }
        return json.dumps(report, indent=4)
    
    #V1
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
        plt.title('Rozkład znalezionych zagrożeń')
        plt.savefig("report/threat_distribution.png")
        plt.show()
    
    def save_suspicious_flows(self):
    
        suspicious_report = {
            "report_id": self.report_id,
            "suspicious_flows": self.suspicious_flows,
            "alerts": {flow_id: [alert.to_dict() for alert in alerts] for flow_id, alerts in self.generated_alerts.items()}
        }

        return json.dumps(suspicious_report, indent=4)
