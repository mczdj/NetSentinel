import sys
import os
import json
import datetime
import getpass
import subprocess
import requests
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal

USERNAME = getpass.getuser()
LAN_API_URL = "http://192.168.1.141:5001"       # For /connect (LAN IP)
TUNNEL_API_URL = "http://10.10.0.1:5001"        # For /logs, etc. (via tunnel)
SERVER_API_URL = TUNNEL_API_URL

WIREGUARD_PATH = "C:\\Program Files\\WireGuard\\wireguard.exe"
WG_EXE_PATH = "C:\\Program Files\\WireGuard\\wg.exe"
CONFIG_FILE = "D:\\NetSentinel\\session.conf"
TUNNEL_NAME = "session"

class ConnectThread(QThread):
    connected = pyqtSignal(str)
    failed = pyqtSignal(str)

    def run(self):
        try:
            private_key, public_key = self.generate_keys()
            response = requests.post(f"{LAN_API_URL}/connect", json={
                "username": USERNAME,
                "public_key": public_key
            })
            response.raise_for_status()
            server_data = response.json()

            self.build_config(private_key, server_data["assigned_ip"], server_data["server_public_key"])
            subprocess.run([WIREGUARD_PATH, '/installtunnelservice', CONFIG_FILE], check=True)
            self.connected.emit(server_data["assigned_ip"])
        except Exception as e:
            self.failed.emit(str(e))

    def generate_keys(self):
        priv_proc = subprocess.run([WG_EXE_PATH, 'genkey'], capture_output=True, text=True, check=True)
        private_key = priv_proc.stdout.strip()
        pub_proc = subprocess.run([WG_EXE_PATH, 'pubkey'], input=private_key, capture_output=True, text=True, check=True)
        public_key = pub_proc.stdout.strip()
        return private_key, public_key

    def build_config(self, private_key, client_ip, server_pubkey):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        server_ip = LAN_API_URL.split("//")[1].split(":")[0]
        config = f"""
[Interface]
PrivateKey = {private_key}
Address = {client_ip}/32
DNS = 10.10.0.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = {server_ip}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 60
"""
        with open(CONFIG_FILE, 'w') as f:
            f.write(config.strip())

class NetSentinelGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel")
        self.setGeometry(100, 100, 400, 500)
        self.is_connected = False
        self.last_log_line = 0

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("NetSentinel")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        user_label = QLabel(f"User: {USERNAME}")
        user_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(user_label)

        self.status_label = QLabel("Status: Disconnected")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: red; font-size: 14px;")
        layout.addWidget(self.status_label)

        self.ip_label = QLabel("VPN IP: N/A")
        self.ip_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.ip_label)

        self.connect_btn = QPushButton("Connect")
        self.connect_btn.setStyleSheet("background-color: green; color: white; font-size: 14px;")
        self.connect_btn.clicked.connect(self.toggle_connection)
        layout.addWidget(self.connect_btn)

        log_label = QLabel("Threat Logs:")
        log_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(log_label)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("background-color: #f4f4f4; font-family: monospace;")
        layout.addWidget(self.log_box)

        self.download_btn = QPushButton("Download Logs")
        self.download_btn.setStyleSheet("font-size: 13px;")
        self.download_btn.clicked.connect(self.download_logs)
        layout.addWidget(self.download_btn)

        self.clear_btn = QPushButton("Clear Logs")
        self.clear_btn.setStyleSheet("font-size: 13px;")
        self.clear_btn.setEnabled(False)
        self.clear_btn.clicked.connect(self.clear_logs)
        layout.addWidget(self.clear_btn)

        self.setLayout(layout)

    def toggle_connection(self):
        self.connect_btn.setEnabled(False)
        if not self.is_connected:
            self.status_label.setText("Status: Connecting...")
            self.status_label.setStyleSheet("color: orange; font-size: 16px;")
            self.thread = ConnectThread()
            self.thread.connected.connect(self.on_connected)
            self.thread.failed.connect(self.on_failed)
            self.thread.start()
        else:
            self.status_label.setText("Status: Disconnecting...")
            self.status_label.setStyleSheet("color: orange; font-size: 16px;")
            try:
                subprocess.run([WIREGUARD_PATH, '/uninstalltunnelservice', TUNNEL_NAME], check=True)
            except Exception as e:
                QMessageBox.warning(self, "Disconnect Failed", str(e))
            if hasattr(self, 'log_timer'):
                self.log_timer.stop()
            self.update_ui(False)

    def on_connected(self, ip):
        global SERVER_API_URL
        SERVER_API_URL = TUNNEL_API_URL
        self.update_ui(True, ip)
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self.load_threat_logs)
        self.log_timer.start(2000)

    def on_failed(self, error):
        QMessageBox.critical(self, "Connection Failed", error)
        self.update_ui(False)

    def update_ui(self, connected, ip="N/A"):
        self.is_connected = connected
        self.connect_btn.setEnabled(True)
        self.clear_btn.setEnabled(connected)

        if connected:
            self.status_label.setText("Status: Connected")
            self.status_label.setStyleSheet("color: green; font-size: 20px;")
            self.ip_label.setText(f"VPN IP: {ip}")
            self.connect_btn.setText("Disconnect")
            self.connect_btn.setStyleSheet("background-color: red; color: white; font-size: 14px;")
        else:
            self.status_label.setText("Status: Disconnected")
            self.status_label.setStyleSheet("color: red; font-size: 20px;")
            self.ip_label.setText("VPN IP: N/A")
            self.connect_btn.setText("Connect")
            self.connect_btn.setStyleSheet("background-color: green; color: white; font-size: 14px;")

    def load_threat_logs(self):
        try:
            response = requests.get(f"{SERVER_API_URL}/logs")
            response.raise_for_status()
            logs = response.json()

            new_logs = logs[self.last_log_line:]
            for entry in new_logs:
                domain = entry.get("domain", "")
                time_str = entry.get("timestamp", "")
                log = f"\u26d4 [{time_str}] Blocked domain: {domain}"
                self.log_box.append(log)

            self.last_log_line = len(logs)
        except Exception as e:
            print(f"[!] Failed to load logs: {e}")

    def download_logs(self):
        try:
            response = requests.get(f"{SERVER_API_URL}/logs")
            response.raise_for_status()
            logs = response.json()

            formatted_logs = ""
            for entry in logs:
                domain = entry.get("domain", "")
                time_str = entry.get("timestamp", "")
                formatted_logs += f"[{time_str}] Blocked domain: {domain}\n"

            downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(downloads_path, exist_ok=True)
            filename = f"netsentinel_threat_logs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            file_path = os.path.join(downloads_path, filename)

            with open(file_path, 'w') as f:
                f.write(formatted_logs)

            QMessageBox.information(self, "Logs Downloaded", f"Logs saved to:\n{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Download Failed", str(e))

    def clear_logs(self):
        if not self.is_connected:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Clear",
            "Are you sure you want to clear all threat logs?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            try:
                response = requests.post(f"{SERVER_API_URL}/clear_logs")
                response.raise_for_status()
                if response.json().get("status") == "cleared":
                    self.log_box.clear()
                    self.last_log_line = 0
                    QMessageBox.information(self, "Logs Cleared", "Threat logs have been cleared.")
                else:
                    QMessageBox.warning(self, "Warning", "Server did not confirm log clearing.")
            except Exception as e:
                QMessageBox.critical(self, "Clear Failed", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetSentinelGUI()
    window.show()
    sys.exit(app.exec_())
