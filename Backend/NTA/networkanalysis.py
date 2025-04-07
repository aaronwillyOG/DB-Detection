from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP

'''Tracker Detection'''
known_trackers = ["google-analytics.com", "doubleclick.net", "facebook.com", "mobile.events.data.microsoft.com"]

def get_sni(packet):
    try:
        raw_data = bytes(packet[TCP].payload)
        if raw_data[0:3] == b'\x16\x03\x01':
            sni_length = raw_data[43]
            sni_start = 44
            sni_end = sni_start + sni_length
            sni = raw_data[sni_start:sni_end].decode('utf-8')
            return sni
    except Exception as e:
        pass
    return None

def detect_trackers(packet):
    # HTTP Tracking Detection
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        host = http_layer.Host.decode()
        if any(tracker in host for tracker in known_trackers):
            return True

    # DNS Tracking Detection
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # DNS query
        dns_query = packet[DNSQR].qname.decode()
        if any(tracker in dns_query for tracker in known_trackers):
           return True

    # HTTPS Tracking Detection using SNI
    if packet.haslayer(TCP) and packet[TCP].dport == 443:  # HTTPS traffic on port 443
        if packet.haslayer(IP):
            sni = get_sni(packet)
            if sni and any(tracker in sni for tracker in known_trackers):
                return True


# Function to process each captured packet
def packet_handler(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        host = http_layer.Host.decode()
        tracker = detect_trackers(packet)
        if tracker:
            # alert_message = f"Tracking detected: {host}"
            # socketio.emit('tracker_alert', {'message': alert_message})
            print(f"Tracking detected: {host}")

    elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # qr == 0 means it's a DNS query
        dns_layer = packet.getlayer(DNSQR)  # DNS Question Record
        dns_query = packet[DNSQR].qname.decode()
        tracker = detect_trackers(packet)
        if tracker:
            # alert_message = f"Tracking detected: {dns_query}"
            # socketio.emit('tracker_alert', {'message': alert_message})
            print(f"Tracking detected: {dns_query}")

    elif packet.haslayer(TCP) and packet[TCP].dport == 443:
        if packet.haslayer(IP):
            sni = get_sni(packet)
            tracker = detect_trackers(packet)
            if tracker:
                # alert_message = f"Tracking detected: {sni}"
                # socketio.emit('tracker_alert', {'message': alert_message})
                print(f"Tracking detected: {sni}")


sniff(iface="Wi-Fi", filter="tcp port 80 or tcp port 443 or udp port 53", prn=packet_handler, store=False)
