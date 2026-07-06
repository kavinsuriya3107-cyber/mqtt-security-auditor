import time
import paho.mqtt.client as mqtt
from mqtt_auditor.modules.base import BaseAuditModule


class TopicsModule(BaseAuditModule):
    """
    Module 3 — Topic Analysis

    This module performs two critical topic-eavesdropping checks:
      1. Wildcard Subscription Audit — Subscribes to '#' to capture all messages
      2. $SYS Topic Leakage Audit — Subscribes to '$SYS/#' for internal broker data

    Module Chaining:
      This module uses credentials discovered by the Auth module (Module 2).
      If anonymous access is available, it uses that. Otherwise, it connects
      using the first valid credential pair found during brute-force.
      If no connection method is available, it reports that and exits gracefully.
    """

    @property
    def name(self):
        return "Topic Analysis"

    @property
    def description(self):
        return "Checks for wildcard '#' subscription and $SYS/ topic leakage."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")

        # Load configurations
        capture_time = self.config.get("modules", {}).get("topics", {}).get("capture_time", 3.0)

        self.results = {
            "wildcard_allowed": False,
            "sys_allowed": False,
            "captured_topics": [],
            "sys_data": {},
            "connection_method": None
        }

        # ──────────────────────────────────────────────
        # STEP 1: Determine how to connect using context
        # ──────────────────────────────────────────────
        port = self._get_connectable_port()
        creds = self._get_best_credentials()

        if port is None:
            print("  [-] No open MQTT ports found in context. Skipping topic analysis.")
            return self.results

        if creds is False:
            print("  [-] No valid credentials or anonymous access available. Skipping topic analysis.")
            return self.results

        username, password = creds
        if username is None:
            self.results["connection_method"] = "anonymous"
            print(f"  [*] Connecting anonymously to port {port}...")
        else:
            self.results["connection_method"] = f"{username}:{password}"
            print(f"  [*] Connecting as '{username}' to port {port}...")

        # ──────────────────────────────────────────────
        # STEP 2: Connect and Subscribe
        # ──────────────────────────────────────────────
        captured_messages = []

        try:
            client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
        except AttributeError:
            client = mqtt.Client()

        if username is not None:
            client.username_pw_set(username, password)

        def on_message(client, userdata, message):
            topic = message.topic
            payload = message.payload.decode("utf-8", errors="ignore")
            captured_messages.append((topic, payload))
            print(f"  [+] Captured: {topic} -> {payload[:50]}")

        client.on_message = on_message

        try:
            client.connect(self.target, port, keepalive=60)
            client.loop_start()

            # Subscribe to wildcard '#' to capture all user messages
            print("  [*] Subscribing to wildcard topic '#'...")
            client.subscribe("#")

            # Subscribe to $SYS/# for internal broker statistics
            print("  [*] Subscribing to system topic '$SYS/#'...")
            client.subscribe("$SYS/#")

            # Eavesdrop for the configured duration
            print(f"  [*] Eavesdropping for {capture_time} seconds...")
            time.sleep(capture_time)

            client.loop_stop()
            client.disconnect()

        except Exception as e:
            print(f"  [-] Connection error during topic analysis: {str(e)}")
            return self.results

        # ──────────────────────────────────────────────
        # STEP 3: Process Captured Messages
        # ──────────────────────────────────────────────
        sys_messages = []
        user_messages = []

        for topic, payload in captured_messages:
            if topic.startswith("$SYS/"):
                sys_messages.append((topic, payload))
            else:
                user_messages.append((topic, payload))

        if user_messages:
            self.results["wildcard_allowed"] = True
            self.results["captured_topics"] = list(set([t for t, _ in user_messages]))
            print(f"  [!] Wildcard subscription allowed! Captured {len(user_messages)} messages across {len(self.results['captured_topics'])} topics.")
        else:
            print("  [-] No user topic data captured (wildcard may be restricted or no traffic).")

        if sys_messages:
            self.results["sys_allowed"] = True
            for topic, payload in sys_messages[:10]:
                self.results["sys_data"][topic] = payload
            print(f"  [!] $SYS topic leakage confirmed! Captured {len(sys_messages)} system metrics.")
        else:
            print("  [-] $SYS topic namespace is secure (no leak detected).")

        # ──────────────────────────────────────────────
        # STEP 4: Register findings
        # ──────────────────────────────────────────────
        self._register_findings(user_messages, sys_messages)

        return self.results

    def _register_findings(self, user_messages, sys_messages):
        """Registers security findings based on captured messages."""
        if self.results["wildcard_allowed"]:
            topics_sample = ", ".join(self.results["captured_topics"][:5])
            self.scorer.add_finding(
                vulnerability_id="wildcard_subscription",
                details=(
                    "Any client can subscribe to the '#' wildcard and read all messages "
                    "passing through the broker without ACL blocks."
                ),
                severity="HIGH",
                evidence=f"Subscribed to '#' and received messages on: {topics_sample}"
            )

        if self.results["sys_allowed"]:
            metrics_sample = "\n".join(
                [f"{k}: {v}" for k, v in list(self.results["sys_data"].items())[:5]]
            )
            self.scorer.add_finding(
                vulnerability_id="sys_topic_leak",
                details=(
                    "$SYS/ internal broker topics are readable by unauthenticated users. "
                    "Attackers can learn broker version, connected client count, and uptime."
                ),
                severity="MEDIUM",
                evidence=f"Read Mosquitto broker statistics from $SYS/broker/version.\n{metrics_sample}"
            )
