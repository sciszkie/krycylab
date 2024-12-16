class Alert:
    def __init__(self, flow_id, alert) -> None:
        self.flow_id = flow_id
        self.alert = alert

    def to_dict(self):
        return {
            'flow_id': self.flow_id,
            'alert': self.alert
        }
