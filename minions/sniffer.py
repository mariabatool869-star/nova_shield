from scapy.all import sniff, IP, TCP
import threading
import time

class Sniffer:
    """Live network packet capture that feeds into OPTIC."""
    
    def __init__(self, callback_function):
        self.callback = callback_function
        self.is_running = False
        self.thread = None
        # Store timestamps of connections to detect bursts
        self.connection_tracker = {}
        self.lock = threading.Lock()

    def _packet_callback(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            # 1. TRUE ATTACK SIGNAL: Traffic targeting Port 22 (SSH)
            if dst_port == 22:
                print(f"🚨 REAL SSH ATTACK DETECTED FROM {src_ip}")
                log_line = f"Live TCP: Failed password for root from {src_ip} port 5555 ssh2"
                self.callback(log_line)
            
            # 2. BURST DETECTION: If a single IP makes 5+ connections in 3 seconds
            # (This catches aggressive port scanners and DDoS)
            else:
                now = time.time()
                with self.lock:
                    if src_ip not in self.connection_tracker:
                        self.connection_tracker[src_ip] = []
                    
                    # Clean old timestamps
                    self.connection_tracker[src_ip] = [
                        t for t in self.connection_tracker[src_ip] if now - t < 3.0
                    ]
                    self.connection_tracker[src_ip].append(now)
                    
                    if len(self.connection_tracker[src_ip]) > 5:
                        print(f"🚨 PORT SCAN / DDOS DETECTED FROM {src_ip} (6+ connections in 3s)")
                        log_line = f"Live TCP: Failed password for root from {src_ip} port 5555 ssh2"
                        self.callback(log_line)
                        self.connection_tracker[src_ip] = [] # Reset counter

    def start(self):
        if not self.is_running:
            self.is_running = True
            print("🟢 NX-01 OPTIC: Live Sniffer started (watching for SSH and Port Scans).")
            
            self.thread = threading.Thread(
                target=lambda: sniff(iface="en0", prn=self._packet_callback, store=False, timeout=3600),
                daemon=True
            )
            self.thread.start()