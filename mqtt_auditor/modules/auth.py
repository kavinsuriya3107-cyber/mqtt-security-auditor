import os
import time
import paho.mqtt.client as mqtt
from mqtt_auditor.modules.base import BaseAuditModule


class AuthModule(BaseAuditModule):
    """
    Module 2 — Authentication Testing

    This module performs two critical authentication audits:
      1. Anonymous Connection Audit — Checks if the broker allows connections
         without any username or password.
      2. Default Credential Brute-Force — Reads a dictionary file containing common
         IoT/MQTT credentials (e.g., admin:admin, guest:guest) and attempts to log in.

    Why this is important:
      - Default passwords are the #1 entry point for botnets (like Mirai).
      - Brokers exposed on the internet with anonymous access leak all pub/sub data.
    """

    @property
    def name(self):
        return "Authentication Testing"

    @property
    def description(self):
        return "Tests for anonymous access and brute-forces default credentials."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")

        # Read ports, wordlist path, and timeout from config
        timeout = self.config.get("timeout", 5.0)
        wordlist_path = self.config.get("wordlist", "wordlists/mqtt_defaults.txt")
        module_config = self.config.get("modules", {}).get("auth", {})

        # Default ports to check (1883 and 1884 are plaintext ports where we test credentials)
        ports = [1883, 1884]

        self.results = {
            "anonymous_allowed": {},
            "default_credentials_found": []
        }

        # ──────────────────────────────────────────────
        # PHASE 1: Anonymous Connection Testing
        # ──────────────────────────────────────────────
        for port in ports:
            print(f"  [*] Testing anonymous access on port {port}...")
            anon_status = self._test_credentials(self.target, port, username=None, password=None, timeout=2.0)
            
            if anon_status["success"]:
                self.results["anonymous_allowed"][str(port)] = True
                print(f"  [+] Port {port}: Anonymous connection ALLOWED!")
            else:
                self.results["anonymous_allowed"][str(port)] = False
                error_msg = anon_status["error"] or f"Code {anon_status['code']}"
                print(f"  [-] Port {port}: Anonymous connection denied ({error_msg})")

        # ──────────────────────────────────────────────
        # PHASE 2: Default Credential Brute-Force
        # ──────────────────────────────────────────────
        # Load credentials from the wordlist file
        credentials_to_test = self._load_wordlist(wordlist_path)
        
        if not credentials_to_test:
            print("  [!] Wordlist empty or missing. Skipping credential brute-force.")
            self._register_findings()
            return self.results

        # Only brute-force on ports that are open and do NOT allow anonymous access
        # (If anonymous is allowed, credential testing is redundant on that port)
        ports_to_brute = [p for p in ports if not self.results["anonymous_allowed"].get(str(p), False)]

        for port in ports_to_brute:
            print(f"  [*] Starting default credential audit on port {port} ({len(credentials_to_test)} pairs)...")
            
            for username, password in credentials_to_test:
                # Debug logging to show progress
                status = self._test_credentials(self.target, port, username, password, timeout=2.0)
                
                if status["success"]:
                    print(f"  [+] SUCCESS: Found credentials [{username}:{password}] on port {port}!")
                    self.results["default_credentials_found"].append({
                        "port": port,
                        "username": username,
                        "password": password
                    })
                    # Keep scanning to find all weak accounts, not just one

        # ──────────────────────────────────────────────
        # PHASE 3: Register findings with the Risk Scorer
        # ──────────────────────────────────────────────
        self._register_findings()

        return self.results

    # ================================================================
    # HELPER METHODS
    # ================================================================

    def _test_credentials(self, host, port, username=None, password=None, timeout=2.0):
        """
        Attempts to connect to the broker using paho-mqtt client with optional credentials.

        Args:
            host: Target host IP/domain
            port: Port number (1883/1884)
            username: Optional username
            password: Optional password
            timeout: Maximum seconds to wait for CONNACK handshake

        Returns:
            dict containing:
              - success (bool): True if connection accepted (rc == 0)
              - code (int): The CONNACK return code (0 = success, 4 = bad credentials, etc.)
              - error (str): Error message if socket/protocol failed
        """
        status = {"success": False, "code": None, "error": None}

        # Initialize paho client.
        # We must support both paho-mqtt v1.x and v2.x (which requires callback_api_version)
        try:
            client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
        except AttributeError:
            client = mqtt.Client()  # Fallback for old paho v1.x installations

        # Set username and password if testing authenticated login
        if username is not None:
            client.username_pw_set(username, password)

        # Non-blocking variables to track network thread
        connected = False
        conn_code = None
        connection_failed = False
        fail_reason = None

        # Define connection callback
        def on_connect(client, userdata, flags, rc):
            nonlocal connected, conn_code
            connected = True
            conn_code = rc

        client.on_connect = on_connect

        try:
            # Attempt to connect to the network socket
            client.connect(host, port, keepalive=60)
            
            # Start the background network loop
            client.loop_start()

            # Wait for on_connect callback to be triggered
            start_time = time.time()
            while not connected and not connection_failed and (time.time() - start_time) < timeout:
                time.sleep(0.1)

            # Stop loop and clean up socket
            client.loop_stop()
            client.disconnect()

            if connected:
                status["code"] = conn_code
                if conn_code == 0:
                    status["success"] = True
                elif conn_code == 4:
                    status["error"] = "Bad username or password"
                elif conn_code == 5:
                    status["error"] = "Not authorized"
                else:
                    status["error"] = f"CONNACK refused (code: {conn_code})"
            else:
                status["error"] = "Handshake timeout"

        except Exception as e:
            status["error"] = str(e)

        return status

    def _load_wordlist(self, filepath):
        """
        Reads username:password credential pairs from a text file.

        File format:
          admin:admin
          admin:password
          user:12345

        Returns:
            list of tuples: [(username, password), ...]
        """
        pairs = []
        if not os.path.exists(filepath):
            # Try running relative to root project workspace
            fallback_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", filepath))
            if os.path.exists(fallback_path):
                filepath = fallback_path
            else:
                return pairs

        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comment lines
                    if not line or line.startswith("#"):
                        continue
                    
                    if ":" in line:
                        parts = line.split(":", 1)
                        pairs.append((parts[0].strip(), parts[1].strip()))
        except Exception as e:
            print(f"  [-] Error loading wordlist: {str(e)}")

        return pairs

    def _register_findings(self):
        """
        Translates audit results into RiskScorer findings.
        """
        # Register Anonymous access vulnerabilities
        for port, allowed in self.results["anonymous_allowed"].items():
            if allowed:
                self.scorer.add_finding(
                    vulnerability_id="anonymous_access",
                    details=(
                        f"The broker allows anonymous connections on port {port}. "
                        "Anyone can connect and read or publish messages without a password."
                    ),
                    severity="CRITICAL",
                    evidence=f"Successfully connected to port {port} with no credentials."
                )

        # Register Default Credentials vulnerabilities
        if self.results["default_credentials_found"]:
            for cred in self.results["default_credentials_found"]:
                port = cred["port"]
                user = cred["username"]
                pwd = cred["password"]
                
                self.scorer.add_finding(
                    vulnerability_id="default_credentials",
                    details=(
                        f"Found weak/default credentials on port {port}: [{user}:{pwd}]. "
                        "An attacker can log in using these default credentials and take full "
                        "control of your system."
                    ),
                    severity="CRITICAL",
                    evidence=f"Connected to port {port} using credentials: '{user}:{pwd}'"
                )
