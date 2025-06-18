from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os
import json

app = Flask(__name__)
CORS(app)

used_ips = set(['10.10.0.1'])
next_ip_octet = 2

def get_next_available_ip():
    global next_ip_octet
    while next_ip_octet < 255:
        ip = f"10.10.0.{next_ip_octet}"
        if ip not in used_ips:
            used_ips.add(ip)
            return ip
        next_ip_octet += 1
    return None

def get_server_public_key():
    with open('/etc/wireguard/server_public.key', 'r') as f:
        return f.read().strip()

@app.route('/connect', methods=['POST'])
def handle_connect():
    data = request.json
    client_public_key = data.get('public_key')
    client_username = data.get('username', 'user')
    if not client_public_key:
        return jsonify({"error": "Public key is missing"}), 400

    assigned_ip = get_next_available_ip()
    if not assigned_ip:
        return jsonify({"error": "No available IP addresses"}), 500

    try:
        command = [
            "sudo", "wg", "set", "wg0", "peer",
            client_public_key, "allowed-ips", f"{assigned_ip}/32"
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)

        print(f"[+] CONNECTION: User '{client_username}' connected with IP {assigned_ip} and key {client_public_key[:10]}...")
        return jsonify({
            "status": "peer_added",
            "assigned_ip": assigned_ip,
            "server_public_key": get_server_public_key()
        })

    except subprocess.CalledProcessError as e:
        print(f"[!] ERROR adding peer: {e.stderr}")
        if assigned_ip in used_ips:
            used_ips.remove(assigned_ip)
        return jsonify({"error": "Failed to set peer on server"}), 500
    except Exception as e:
        print(f"[!] ERROR: An unexpected error occurred: {e}")
        if assigned_ip in used_ips:
            used_ips.remove(assigned_ip)
        return jsonify({"error": "An unexpected error occurred on the server"}), 500

@app.route('/disconnect', methods=['POST'])
def handle_disconnect():
    data = request.json
    client_public_key = data.get('public_key')
    client_username = data.get('username', 'user')
    if not client_public_key:
        return jsonify({"error": "Public key is missing"}), 400

    command = ["sudo", "wg", "set", "wg0", "peer", client_public_key, "remove"]
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"[-] DISCONNECTION: User '{client_username}' with key {client_public_key[:10]}... disconnected.")
        return jsonify({"status": "peer_removed"})
    except subprocess.CalledProcessError as e:
        print(f"[*] INFO on disconnect: {e.stderr}")
        return jsonify({"status": "peer_not_found_or_error"})

@app.route("/logs", methods=["GET"])
def get_threat_logs():
    log_path = os.path.join(os.getcwd(), "threat_log.jsonl")
    if not os.path.exists(log_path):
        return jsonify([])

    try:
        with open(log_path, "r") as f:
            lines = f.readlines()
            logs = [json.loads(line.strip()) for line in lines if line.strip()]
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/clear_logs", methods=["POST"])
def clear_threat_logs():
    log_path = os.path.join(os.getcwd(), "threat_log.jsonl")
    try:
        with open(log_path, "w") as f:
            f.write("")
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
