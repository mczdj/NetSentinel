# NetSentinel

NetSentinel is an automated phishing detection and DNS security tool designed for Small and Medium-sized Enterprises (SMEs) in the UAE. It provides secure VPN-based traffic routing, DNS-layer threat filtering, and a simple GUI dashboard for end users.

---

## 🔒 Features

- ✅ **WireGuard VPN Integration** – Encrypts all traffic between client and server.
- ✅ **Real-Time DNS Filtering** – Blocks phishing, malware, and malicious domains.
- ✅ **Threat Logging** – Records all blocked domains for audit and review.
- ✅ **GUI Client App** – Simple one-click interface using PyQt5.
- ✅ **Custom Blocklist Support** – Extend protection with your own rules.
- ✅ **Multi-user IP Assignment** – Each user gets a private virtual IP.

---

## 🧱 Architecture Overview

NetSentinel uses a 3-tier design:

- **Client Layer:** Python GUI + WireGuard config management.
- **Server Layer:** Flask API that handles connect/disconnect/logs.
- **DNS Layer:** Python DNS proxy that intercepts and filters traffic.

---

## 📁 Project Files

```
NetSentinel/
├── client_app.py           # GUI client (older version)
├── Client_app2.0.py        # GUI client (enhanced version)
├── api_server.py           # Flask server API
├── dns_proxy.py            # DNS filter proxy
├── session.conf            # WireGuard config for the client
├── blocklist.json          # Malicious domains list
└── README.md               # Project documentation
```

---

## ⚙️ How to Use

### 🖥 Client

1. Install WireGuard on your system.
2. Run:
   ```bash
   python Client_app2.0.py
   ```
3. Click “Connect” to establish the VPN tunnel and begin filtering.

---

### 🌐 Server

1. Start the Flask API:
   ```bash
   sudo python3 api_server.py
   ```

2. Run DNS proxy on port 5333:
   ```bash
   sudo python3 dns_proxy.py
   ```

---

## 📦 Requirements

Install these dependencies:

```bash
pip install flask dnslib pyqt5 requests
```

Make sure WireGuard is installed and added to your system path.

---

## 👥 Team Members

- **Mohamed Ibrahim Idris**
- **Ameen Murtaza Siddiqui**
- **Ahmed Mohammed Hussein**

---

## 🛡️ Project Goal

To deliver a unified, low-cost, endpoint security solution that protects against phishing, DNS hijacking, and MITM attacks — empowering UAE SMEs to defend their data without needing a dedicated IT team.
