from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP, UDP
import threading

app = Flask(__name__)

# Shared list to store packets
captured_packets = []

def process_packet(packet):
    packet_info = {}
    if IP in packet:
        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst
        packet_info["protocol"] = packet[IP].proto

        if packet.haslayer(TCP):
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport

        # Keep only the latest 50 packets
        if len(captured_packets) > 50:
            captured_packets.pop(0)
        captured_packets.append(packet_info)

def start_sniffing():
    sniff(prn=process_packet, store=False)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def get_packets():
    return jsonify(captured_packets)

if __name__ == "__main__":
    # Run sniffer in background
    t = threading.Thread(target=start_sniffing, daemon=True)
    t.start()
    app.run(host="127.0.0.1", port=5000, debug=True)
