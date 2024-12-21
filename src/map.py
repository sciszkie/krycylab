import requests
import folium
import time

#E1 i V2
class Map:
    def __init__(self):
        self.map = folium.Map([20.0, 0.0], zoom_start=2)

    def get_ip_location(self, ip:str):
        data=requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        latitude=data["latitude"]
        longitude=data["longitude"]
        return (latitude,longitude)

    def printing_map(self, stream):
        how_many_addresses = 0
        feature_group=folium.FeatureGroup("Threats")
        for flow in stream:
            ip = flow.dst_ip  
            lat,log=self.get_ip_location(ip)
            how_many_addresses+=1
            if(type(lat)!=float or type(log)!=float):
                continue
            feature_group.add_child(folium.Marker([lat,log], popup=ip))
        self.map.add_child(feature_group)
        self.map.save('report/map.html')
