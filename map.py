import folium
import geocoder

class Map():
    def printing_map(self,stream):
        map = folium.Map([20.0,0.0],zoom_start=2)
        how_many_addreses=0
        for flow in stream:
            ip=flow.src_ip
            g=geocoder.ip(ip)
            if(g.ok and g.latlng):
                how_many_addreses+=1
                print(how_many_addreses)
                location=g.latlng
                folium.CircleMarker(location=location,radius=50,color="red").add_to(map)
                folium.Marker(location,popup=ip).add_to(map)
            else:
                print("Nie moge dodac adreesu na mape")
        map.save('map.html')