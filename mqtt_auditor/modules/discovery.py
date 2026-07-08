import socket
import ssl
from mqtt_auditor.modules.base import BaseAuditModule


class DiscoveryModule(BaseAuditModule):
    """
    Module 1 — Broker Discovery

    This module performs three critical reconnaissance tasks:
      1. TCP Port Scanning — Checks if MQTT ports (1883/1884/8883) are open
      2. MQTT Protocol Verification — Sends a raw CONNECT packet and reads the CONNACK
         response to confirm the service is actually an MQTT broker
      3. TLS Availability Check — Attempts an SSL/TLS handshake on port 8883 to determine
         if encrypted communication is supported

    Why raw sockets instead of paho-mqtt?
      - Speed: Raw sockets are faster for discovery (no library overhead)
      - Stealth: Minimal interaction with the broker
      - Learning: You understand MQTT at the byte/packet level (EEE advantage)
    """

    @property
    def name(self):
        return "Broker Discovery"

    @property
    def description(self):
        return "Scans ports, verifies MQTT protocol, and checks TLS availability."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")

        # Read port list and timeout from config, or use safe defaults
        module_config = self.config.get("modules", {}).get("discovery", {})
        ports = module_config.get("ports", [1883, 1884, 8883])
        timeout = self.config.get("timeout", 5.0)

        # Store all results in a structured dictionary
        self.results = {
            "ports": {},
            "mqtt_confirmed": False,
            "tls_available": False,
            "tls_ports": [],
            "broker_info": None,
            "connack_code": None
        }

        # ──────────────────────────────────────────────
        # PHASE 1: TCP Port Scanning
        # ──────────────────────────────────────────────
        open_ports = []
        for port in ports:
            status = self._scan_port(self.target, port, timeout)
            self.results["ports"][str(port)] = status
            if status == "OPEN":
                open_ports.append(port)
                print(f"  [+] Port {port}: OPEN")
            else:
                print(f"  [-] Port {port}: {status}")

        # If no ports are open, there is nothing more to do
        if not open_ports:
            print("  [!] No MQTT ports are open. Target may not be an MQTT broker.")
            return self.results

        # ──────────────────────────────────────────────
        # PHASE 2: MQTT Protocol Verification
        # Sends a raw CONNECT packet to confirm it speaks MQTT
        # ──────────────────────────────────────────────
        # Try plaintext ports first (1883, 1884)
        plaintext_ports = [p for p in open_ports if p != 8883]
        for port in plaintext_ports:
            connack = self._send_mqtt_connect(self.target, port, timeout)
            if connack is not None:
                self.results["mqtt_confirmed"] = True
                self.results["connack_code"] = connack
                print(f"  [+] MQTT service CONFIRMED on port {port} (CONNACK code: {connack})")
                break

        # ──────────────────────────────────────────────
        # PHASE 3: TLS Availability Check
        # Attempts SSL handshake on all candidate TLS ports
        # ──────────────────────────────────────────────
        tls_candidate_ports = [p for p in open_ports if p not in [1883, 1884]]
        tls_successes = []

        for port in tls_candidate_ports:
            tls_info = self._check_tls(self.target, port, timeout)
            if tls_info["success"]:
                tls_successes.append((port, tls_info))
                print(f"  [+] TLS available on port {port}")
                print(f"      Protocol: {tls_info.get('protocol', 'unknown')}")
                print(f"      Cipher: {tls_info.get('cipher', 'unknown')}")
            else:
                print(f"  [-] TLS handshake FAILED on port {port}: {tls_info.get('error')}")

        if tls_successes:
            self.results["tls_available"] = True
            self.results["tls_ports"] = [port for port, _ in tls_successes]
            self.results["broker_info"] = tls_successes[0][1]

        # ──────────────────────────────────────────────
        # PHASE 4: Register findings with the Risk Scorer
        # ──────────────────────────────────────────────
        self._register_findings(open_ports)

        return self.results

    # ================================================================
    # HELPER METHODS — Each one does exactly one job
    # ================================================================

    def _scan_port(self, host, port, timeout):
        """
        Attempts a TCP connection to a specific port.

        How it works (EEE analogy):
          Think of this like checking if a wire is connected.
          We send a signal (SYN) to the target port.
          If the port replies (SYN-ACK), the wire is live = port is OPEN.
          If no reply or rejection (RST), the wire is dead = port is CLOSED.

        Args:
            host: Target IP address (e.g., "127.0.0.1")
            port: Port number to check (e.g., 1883)
            timeout: How many seconds to wait before giving up

        Returns:
            "OPEN", "CLOSED", or "ERROR: <reason>"
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                return "OPEN"
            else:
                return "CLOSED"
        except socket.timeout:
            return "CLOSED (timeout)"
        except socket.gaierror:
            # gaierror = "Get Address Info" error (DNS resolution failed)
            return "ERROR: DNS resolution failed"
        except OSError as e:
            return f"ERROR: {str(e)}"
        finally:
            sock.close()

    def _build_mqtt_connect_packet(self, client_id="mqtt_auditor_probe"):
        """
        Builds a raw MQTT 3.1.1 CONNECT packet from scratch.

        MQTT Packet Structure (what we are building byte-by-byte):
        ┌──────────────────────────────────────────────────────┐
        │ Fixed Header                                         │
        │   Byte 1: 0x10 (Packet Type = CONNECT)              │
        │   Byte 2: Remaining Length (how many bytes follow)   │
        ├──────────────────────────────────────────────────────┤
        │ Variable Header                                      │
        │   Bytes 3-4:   Protocol Name Length (0x00, 0x04)     │
        │   Bytes 5-8:   Protocol Name ("MQTT")               │
        │   Byte 9:      Protocol Level (0x04 = MQTT 3.1.1)   │
        │   Byte 10:     Connect Flags (0x02 = Clean Session)  │
        │   Bytes 11-12: Keep Alive (0x00, 0x3C = 60 seconds) │
        ├──────────────────────────────────────────────────────┤
        │ Payload                                              │
        │   Bytes 13-14: Client ID Length                      │
        │   Bytes 15+:   Client ID string                     │
        └──────────────────────────────────────────────────────┘

        Returns:
            bytes: The complete MQTT CONNECT packet ready to send over TCP
        """
        # --- Variable Header ---
        protocol_name = b"MQTT"
        protocol_level = 4          # MQTT 3.1.1
        connect_flags = 0x02        # Clean Session = 1, no auth
        keepalive = 60              # 60 seconds

        variable_header = (
            len(protocol_name).to_bytes(2, "big")  # Protocol name length
            + protocol_name                          # "MQTT"
            + bytes([protocol_level])                # Version 3.1.1
            + bytes([connect_flags])                 # Clean session
            + keepalive.to_bytes(2, "big")           # Keep alive timer
        )

        # --- Payload ---
        client_id_bytes = client_id.encode("utf-8")
        payload = len(client_id_bytes).to_bytes(2, "big") + client_id_bytes

        # --- Fixed Header ---
        packet_type = 0x10  # CONNECT packet type
        remaining_length = len(variable_header) + len(payload)

        # Combine everything into one packet
        packet = bytes([packet_type, remaining_length]) + variable_header + payload

        return packet

    def _parse_connack(self, response):
        """
        Parses the MQTT CONNACK response from the broker.

        Expected CONNACK Structure:
        ┌───────────────────────────────────────────┐
        │ Byte 0: 0x20 (Packet Type = CONNACK)     │
        │ Byte 1: 0x02 (Remaining Length = 2 bytes) │
        │ Byte 2: Session Present Flag              │
        │ Byte 3: Return Code                       │
        └───────────────────────────────────────────┘

        Return Codes:
          0 = Connection Accepted (broker allowed us in)
          1 = Unacceptable Protocol Version
          2 = Client ID Rejected
          3 = Server Unavailable
          4 = Bad Username/Password
          5 = Not Authorized

        Returns:
            int: The return code (0-5), or None if response is invalid
        """
        if len(response) < 4:
            return None

        # Check if first byte is 0x20 (CONNACK packet type)
        if response[0] != 0x20:
            return None

        # Check if remaining length is 2
        if response[1] != 0x02:
            return None

        # Byte 3 is the return code
        return response[3]

    def _send_mqtt_connect(self, host, port, timeout):
        """
        Sends a raw MQTT CONNECT packet and reads the CONNACK response.

        This is the core verification step:
          1. Open a TCP connection to the target
          2. Send our hand-crafted CONNECT packet (bytes)
          3. Read the response bytes
          4. Parse the CONNACK to confirm it is an MQTT broker

        Returns:
            int: CONNACK return code (0 = accepted), or None if not MQTT
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((host, port))

            # Build and send our CONNECT packet
            connect_packet = self._build_mqtt_connect_packet()
            sock.sendall(connect_packet)

            # Read the CONNACK response (4 bytes expected)
            response = sock.recv(4)

            # Parse and return the result
            return self._parse_connack(response)

        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            sock.close()

    def _check_tls(self, host, port, timeout):
        """
        Attempts a TLS handshake on the given port.

        How TLS works (simplified for EEE understanding):
          1. Our tool says: "I want to talk securely" (ClientHello)
          2. Broker replies with its certificate + chosen cipher (ServerHello)
          3. Both sides agree on encryption keys
          4. All future communication is encrypted

        We use ssl.CERT_NONE because we are auditing, not trusting.
        We want to see WHAT certificate the broker presents, even if it is
        self-signed or expired. A real client would reject bad certs.

        Returns:
            dict with keys: success, protocol, cipher, error
        """
        result = {"success": False, "protocol": None, "cipher": None, "error": None}

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)

        try:
            raw_sock.connect((host, port))

            # Create SSL context (we accept any cert for auditing purposes)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Wrap the raw TCP socket with TLS
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

            # If we reach here, TLS handshake succeeded
            result["success"] = True
            result["protocol"] = tls_sock.version()         # e.g., "TLSv1.3"
            result["cipher"] = tls_sock.cipher()[0]          # e.g., "TLS_AES_256_GCM_SHA384"

            tls_sock.close()

        except ssl.SSLError as e:
            result["error"] = f"TLS handshake failed: {str(e)}"
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["error"] = f"Connection error: {str(e)}"
        finally:
            raw_sock.close()

        return result

    def _register_findings(self, open_ports):
        """
        Analyzes the scan results and registers vulnerabilities with the scorer.

        This method translates raw scan data into security findings:
          - Port 1883 open = plaintext communication risk
          - MQTT confirmed without auth = potential anonymous access
          - Port 8883 closed = no TLS encryption available
        """
        # Finding: Plaintext MQTT port is open
        if 1883 in open_ports:
            self.scorer.add_finding(
                vulnerability_id="plaintext_transmission",
                details=(
                    "Port 1883 (unencrypted MQTT) is open. All messages, "
                    "including credentials and sensor data, can be intercepted "
                    "by anyone on the same network using tools like Wireshark."
                ),
                severity="HIGH",
                evidence=f"TCP connection to {self.target}:1883 succeeded."
            )

        # Finding: MQTT broker confirmed and accepted connection without auth
        if self.results.get("connack_code") == 0:
            self.scorer.add_finding(
                vulnerability_id="anonymous_access",
                details=(
                    "The broker accepted a CONNECT packet without any "
                    "username or password. This means anonymous access "
                    "is enabled (allow_anonymous = true in config)."
                ),
                severity="CRITICAL",
                evidence=(
                    f"Sent MQTT CONNECT to {self.target} with no credentials. "
                    f"Received CONNACK with return code 0 (Connection Accepted)."
                )
            )

        # Finding: No TLS available
        if not self.results.get("tls_available") and 8883 not in open_ports:
            self.scorer.add_finding(
                vulnerability_id="no_tls",
                details=(
                    "Port 8883 (MQTT over TLS) is not available. "
                    "The broker does not support encrypted communication. "
                    "All data is transmitted in plaintext."
                ),
                severity="CRITICAL",
                evidence=f"TCP connection to {self.target}:8883 was refused or timed out."
            )

        # Finding: TLS handshake failed (port open but TLS broken)
        if 8883 in open_ports and not self.results.get("tls_available"):
            self.scorer.add_finding(
                vulnerability_id="weak_tls_configuration",
                details=(
                    "Port 8883 is open but TLS handshake failed. "
                    "This could indicate a misconfigured certificate, "
                    "expired certificate, or incompatible TLS version."
                ),
                severity="MEDIUM",
                evidence=f"TLS error: {self.results.get('broker_info', {}).get('error', 'unknown')}"
            )
