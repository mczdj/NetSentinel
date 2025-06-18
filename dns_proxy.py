import socketserver
from dnslib import DNSRecord
import json
import socket
import time

BLOCKLIST = set()
LOG_FILE = "threat_log.jsonl"

def load_blocklist():
    global BLOCKLIST
    try:
        with open("blocklist.json", "r") as f:
            BLOCKLIST = set(json.load(f))
        print(f"[+] Loaded {len(BLOCKLIST)} blocked domains.")
    except Exception as e:
        print(f"[!] Failed to load blocklist: {e}")

def log_threat(domain):
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "domain": domain
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[!] Failed to log threat: {e}")

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip('.')
            print(f"[DNS] Query: {qname}")

            if any(qname.endswith(domain) for domain in BLOCKLIST):
                print(f"[BLOCKED] {qname}")
                log_threat(qname)
                reply = request.reply()
                reply.header.rcode = 3  # NXDOMAIN
                sock.sendto(reply.pack(), self.client_address)
                return

            # Forward to upstream DNS (e.g. Google)
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(2)
            upstream.sendto(data, ("8.8.8.8", 53))
            response, _ = upstream.recvfrom(512)
            sock.sendto(response, self.client_address)
            upstream.close()

        except Exception as e:
            print(f"[!] DNS error: {e}")
            try:
                reply = request.reply()
                reply.header.rcode = 2  # SERVFAIL
                sock.sendto(reply.pack(), self.client_address)
            except:
                pass

if __name__ == "__main__":
    load_blocklist()
    print("[*] DNS Proxy Running on UDP :5333 (Forwarding to Google DNS)")
    server = socketserver.UDPServer(("0.0.0.0", 5333), DNSHandler)
    server.serve_forever()
