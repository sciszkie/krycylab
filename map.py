import requests
import folium
import time

class Map:
    def __init__(self):
        self.map = folium.Map([20.0, 0.0], zoom_start=2)  # Tworzymy mapę na początku

    def get_ip_location(self, ip:str):
        print(ip)
        data=requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        latitude=data["latitude"]
        longitude=data["longitude"]
        return (latitude,longitude)

    def printing_map(self, stream):
        """ Funkcja do przetwarzania strumienia adresów IP """
        how_many_addresses = 0
        feature_group=folium.FeatureGroup("Threats")
        for flow in stream:
            ip = flow.dst_ip  
            lat,log=self.get_ip_location(ip)
            how_many_addresses+=1
            print(lat)
            print(log)
            if(type(lat)!=float or type(log)!=float):
                print("Nie moge dodac")
                continue
            feature_group.add_child(folium.Marker([lat,log], popup=ip))
            print(f"Dodałem adres: {ip}")
        self.map.add_child(feature_group)
        self.map.save('map.html')
        print(f"Na mapie jest {how_many_addresses} adresów IP.")
