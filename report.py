import json
from typing import List
from uuid import uuid4
from alert import Alert
from nfstream import NFStreamer
import pandas as pd

class Report:
    def __init__(self) -> None:
        self.report_id: str = str(uuid4())
        self.data = []
        self.generated_alerts: List[Alert] = []

    def create_alert(self, flow_id, flow_src_ip):
        message = f"Suspicious large flow to port 443 from {flow_src_ip}"
        alert = Alert(flow_id, message)
        self.generated_alerts.append(alert)

    def stream_info(self, data):
        data_json = data.to_dict(orient='records')
        self.data = data_json

    def to_json(self):
        report = {
            "report_id": self.report_id,
            "flows": self.data,
            "alerts": [alert.to_dict() for alert in self.generated_alerts]
        }
        return json.dumps(report, indent=4)
