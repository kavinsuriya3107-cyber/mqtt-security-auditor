import socket
from mqtt_auditor.modules.base import BaseAuditModule

class DiscoveryModule(BaseAuditModule):
    @property
    def name(self):
        return "Broker Discovery"

    @property
    def description(self):
        return "Scans ports and extracts the MQTT broker banner/version."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")
        
        # Ports we want to scan (from config or defaults)
        ports = self.config.get("modules", {}).get("discovery", {}).get("ports", [1883, 1884, 8883])
        
        self.results = {"ports": {}}

        for port in ports:
            # Create a simple TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)  # Stop waiting after 2 seconds
            
            try:
                # Try to connect to the target IP on the specific port
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    # 0 means connection succeeded (Port is OPEN)
                    self.results["ports"][str(port)] = "OPEN"
                    print(f"[+] Port {port}: OPEN")
                    
                    # Log a finding for Port 1883 if it's open (Plaintext risk)
                    if port == 1883:
                        self.scorer.add_finding(
                            vulnerability_id="plaintext_transmission",
                            details="Port 1883 (unencrypted MQTT) is open.",
                            severity="HIGH",
                            evidence="Port 1883 TCP connection established."
                        )
                else:
                    self.results["ports"][str(port)] = "CLOSED"
                    
            except Exception as e:
                self.results["ports"][str(port)] = f"ERROR: {str(e)}"
            finally:
                sock.close()

        return self.results
