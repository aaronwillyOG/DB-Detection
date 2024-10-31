from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR

def packet_handler(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        print(f"Http Request >> {http_layer.Host} {http_layer.Path}")
    elif packet.haslayer(DNSQR):
        dns_request = packet[DNSQR].qname.decode()
        print(f"DNS Request >> {dns_request}")
    else:
        print(None)

def detect_trackers(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        host = http_layer.Host.decode()
        if any(tracker in host for tracker in known_trackers):
            print(f"Tracking detected: {host}")


known_trackers = ["google_analytics.com", "doubleclick.net", "facebook.com"]

sniff(iface="Wi-Fi", filter="tcp port 80 or tcp port 443 or udp port 53", prn=packet_handler, store=False)
# sniff(filter="tcp port 80", prn=packet_handler, store=False)