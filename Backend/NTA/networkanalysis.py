from flask import Flask, jsonify
from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP
import threading

app = Flask(__name__)

known_trackers = [
    "google-analytics.com", "doubleclick.net",
    "facebook.com", "mobile.events.data.microsoft.com"
]

def get_sni(packet):
    try:
        raw_data = bytes(packet[TCP].payload)
        if raw_data[0:3] == b'\x16\x03\x01':
            sni_length = raw_data[43]
            sni_start = 44
            sni_end = sni_start + sni_length
            sni = raw_data[sni_start:sni_end].decode('utf-8')
            return sni
    except Exception:
        pass
    return None

detected_trackers = []

def detect_trackers(packet):
    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode()
        if any(tracker in host for tracker in known_trackers):
            detected_trackers.append(host)
            return True
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        dns_query = packet[DNSQR].qname.decode()
        if any(tracker in dns_query for tracker in known_trackers):
            detected_trackers.append(dns_query)
            return True
    if packet.haslayer(TCP) and packet[TCP].dport == 443 and packet.haslayer(IP):
        sni = get_sni(packet)
        if sni and any(tracker in sni for tracker in known_trackers):
            detected_trackers.append(sni)
            return True
    return False

def packet_handler(packet):
    detect_trackers(packet)

def start_sniffing():
    sniff(filter="tcp port 80 or tcp port 443 or udp port 53", prn=packet_handler, store=False)

@app.route('/')
def index():
    return "Tracker Detection Service Running"

@app.route('/trackers')
def trackers():
    return jsonify({"detected": list(set(detected_trackers))})

if __name__ == '__main__':
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()
    app.run(host='0.0.0.0', port=8080)
