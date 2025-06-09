from datetime import datetime
import threading

from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import sniff, IP, TCP

app = Flask(__name__)
CORS(app)

captured_packets = []

def packet_handler(pkt):
    if IP in pkt:
        packet_data = {
            "time" : datetime.now().strftime("%H:%M:%S"),
            "src": pkt[IP].src,
            "dst": pkt[IP].dst,
            "protocol": pkt[IP].proto
        }
        captured_packets.append(packet_data)
        if len(captured_packets) > 50:
            captured_packets.pop(0)

sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_handler, store=0))
sniff_thread.daemon = True
sniff_thread.start()

@app.route("/api/packets")
def get_packets():
    return jsonify(captured_packets)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)