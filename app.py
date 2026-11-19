from flask import Flask, jsonify, render_template
from threading import Lock
import time

app = Flask(__name__)

# Shared dashboard data structure linked to real backend metrics
data_lock = Lock()
stats = {
    "total_packets": 0,
    "threats": 0,
    "blocked_ips": set(),
    "history": []
}

# Variable to track packet rate calculation
last_packet_count = 0
last_time = time.time()
current_packet_rate = 0.0

def update_backend_metrics(packet_size: int, is_threat: bool, src_ip: str = None, is_blocked: bool = False):
    """
    Called by live_sniffer.py to feed real data directly into the dashboard!
    """
    global last_packet_count, last_time, current_packet_rate
    with data_lock:
        stats["total_packets"] += 1
        
        if is_threat:
            stats["threats"] += 1
            
        if is_blocked and src_ip:
            stats["blocked_ips"].add(src_ip)
            
        # Calculate live packet rate per second
        now = time.time()
        time_diff = now - last_time
        if time_diff >= 1.0:
            current_packet_rate = (stats["total_packets"] - last_packet_count) / time_diff
            last_packet_count = stats["total_packets"]
            last_time = now
            
            # Store history point every second
            stats["history"].append({
                "time": time.strftime("%H:%M:%S"),
                "packets": stats["total_packets"],
                "threats": stats["threats"]
            })
            stats["history"] = stats["history"][-20:] # Keep last 20 data points

# Main dashboard route
@app.route("/")
def home():
    return render_template("index.html")

# REST API 1: Get live statistics
@app.route("/api/stats", methods=["GET"])
def get_stats():
    with data_lock:
        total = stats["total_packets"]
        threats = stats["threats"]
        percentage = (threats / total) * 100 if total > 0 else 0

        return jsonify({
            "total_packets": total,
            "threats": threats,
            "threat_percentage": round(percentage, 2),
            "blocked_count": len(stats["blocked_ips"]),
            "packet_rate": round(current_packet_rate, 2)
        })

# REST API 2: Get blocked IP addresses
@app.route("/api/blocked-ips", methods=["GET"])
def get_blocked_ips():
    with data_lock:
        ip_list = sorted(list(stats["blocked_ips"]))
    return jsonify({
        "blocked_ips": ip_list
    })

# REST API 3: Get traffic history
@app.route("/api/traffic", methods=["GET"])
def get_traffic():
    with data_lock:
        history = list(stats["history"])
    return jsonify({
        "history": history
    })

if __name__ == "__main__":
    print("NetLock Phase 3 Dashboard Started!")
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(debug=False, use_reloader=False)