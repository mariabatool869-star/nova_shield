from scapy.all import sniff, IP, TCP
import threading
import time

class Sniffer:
    """Live network packet capture that feeds into OPTIC."""
    
    def __init__(self, callback_function):
        self.callback = callback_function
        self.is_running = False
        self.thread = None
        self.connection_tracker = {}
        self.lock = threading.Lock()

    def _packet_callback(self, packet):
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            # Only track external-to-internal or SSH traffic to reduce noise
            if dst_port == 22 or dst_port == 5000:
                now = time.time()
                with self.lock:
                    if src_ip not in self.connection_tracker:
                        self.connection_tracker[src_ip] = []
                    
                    self.connection_tracker[src_ip] = [
                        t for t in self.connection_tracker[src_ip] if now - t < 3.0
                    ]
                    self.connection_tracker[src_ip].append(now)
                    
                    count = len(self.connection_tracker[src_ip])
                    
                    if count > 5:
                        print(f"🚨 BURST DETECTED: {src_ip} ({count} connections in 3s)")
                        # Pass the REAL data to OPTIC
                        log_line = f"Live TCP: {count} connections from {src_ip} on port {dst_port}"
                        self.callback(log_line)
                        self.connection_tracker[src_ip] = []

    def start(self):
        if not self.is_running:
            self.is_running = True
            print("🟢 NX-01 OPTIC: Live Sniffer started (watching for real bursts).")
            
            self.thread = threading.Thread(
                target=lambda: sniff(iface="en0", prn=self._packet_callback, store=False, timeout=3600),
                daemon=True
            )
            self.thread.start()