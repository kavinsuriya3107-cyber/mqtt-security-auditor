import time
import uuid
import paho.mqtt.client as mqtt
from mqtt_auditor.modules.base import BaseAuditModule


class AclModule(BaseAuditModule):
    """
    Module 4 — ACL Verification (Access Control Lists)

    This module tests authorization controls by checking if users can
    publish or subscribe to topics outside their permitted scope.

    Module Chaining:
      - Uses valid_credentials from auth module (no hardcoded passwords)
      - Uses captured_topics from topics module (no hardcoded topic paths)
      - Falls back to common industrial topic patterns if no topics discovered

    Test Strategy:
      1. If two different credential sets exist, test cross-user isolation
         (can user B publish to user A's topics?)
      2. If only one credential set exists, test if that user can publish
         to restricted system topics like '$SYS/'
      3. If anonymous access exists, test if anonymous can publish to
         discovered topics
    """

    # Common industrial MQTT topic patterns to test against when
    # no topics were discovered by the topics module
    FALLBACK_TEST_TOPICS = [
        "cmd/control",
        "admin/config",
        "system/restart",
        "factory/plc/command",
        "device/firmware/update",
    ]

    @property
    def name(self):
        return "ACL Verification"

    @property
    def description(self):
        return "Tests for publish/subscribe isolation and ACL bypass vulnerabilities."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")

        self.results = {
            "acl_bypass_detected": False,
            "unauthorized_publishes": [],
            "topics_tested": [],
            "error": None
        }

        # ──────────────────────────────────────────────
        # STEP 1: Determine test topics from context
        # ──────────────────────────────────────────────
        discovered_topics = self.context.get("captured_topics", [])
        if discovered_topics:
            test_topics = discovered_topics[:5]  # Test up to 5 discovered topics
            print(f"  [*] Using {len(test_topics)} topics discovered by topic analysis module.")
        else:
            test_topics = self.FALLBACK_TEST_TOPICS
            print(f"  [*] No topics from context. Using {len(test_topics)} common industrial patterns.")

        self.results["topics_tested"] = test_topics

        # ──────────────────────────────────────────────
        # STEP 2: Determine credentials from context
        # ──────────────────────────────────────────────
        valid_creds = self.context.get("valid_credentials", [])
        anonymous_ports = self.context.get("anonymous_ports", [])
        open_ports = self.context.get("open_ports", [1883])

        # Pick the port to test on
        port = open_ports[0] if open_ports else 1883

        # ──────────────────────────────────────────────
        # STEP 3: Run ACL bypass tests
        # ──────────────────────────────────────────────

        # Strategy A: Test anonymous publish to discovered/common topics
        if anonymous_ports:
            anon_port = anonymous_ports[0]
            print(f"  [*] Testing anonymous publish rights on port {anon_port}...")
            for topic in test_topics:
                bypassed = self._test_publish(
                    port=anon_port,
                    publisher_user=None,
                    publisher_pass=None,
                    listener_user=valid_creds[0]["username"] if valid_creds else None,
                    listener_pass=valid_creds[0]["password"] if valid_creds else None,
                    topic=topic
                )
                if bypassed:
                    self.results["acl_bypass_detected"] = True
                    self.results["unauthorized_publishes"].append({
                        "user": "anonymous",
                        "topic": topic,
                        "port": anon_port
                    })

        # Strategy B: Test cross-user isolation (if multiple creds exist)
        if len(valid_creds) >= 2:
            cred_a = valid_creds[0]
            cred_b = valid_creds[1]
            print(f"  [*] Testing cross-user isolation: '{cred_b['username']}' → topics accessible to '{cred_a['username']}'...")
            for topic in test_topics:
                bypassed = self._test_publish(
                    port=cred_a["port"],
                    publisher_user=cred_b["username"],
                    publisher_pass=cred_b["password"],
                    listener_user=cred_a["username"],
                    listener_pass=cred_a["password"],
                    topic=topic
                )
                if bypassed:
                    self.results["acl_bypass_detected"] = True
                    self.results["unauthorized_publishes"].append({
                        "user": cred_b["username"],
                        "topic": topic,
                        "port": cred_a["port"]
                    })

        # Strategy C: Single credential — test publish to restricted patterns
        elif len(valid_creds) == 1:
            cred = valid_creds[0]
            restricted_topics = ["$SYS/broker/config", "admin/restart", "cmd/shutdown"]
            print(f"  [*] Testing '{cred['username']}' publish rights to restricted topics...")
            for topic in restricted_topics:
                bypassed = self._test_publish(
                    port=cred["port"],
                    publisher_user=cred["username"],
                    publisher_pass=cred["password"],
                    listener_user=cred["username"],
                    listener_pass=cred["password"],
                    topic=topic
                )
                if bypassed:
                    self.results["acl_bypass_detected"] = True
                    self.results["unauthorized_publishes"].append({
                        "user": cred["username"],
                        "topic": topic,
                        "port": cred["port"]
                    })

        if not valid_creds and not anonymous_ports:
            self.results["error"] = "No credentials or anonymous access available for ACL testing."
            print("  [-] Cannot test ACLs without valid credentials or anonymous access.")
            return self.results

        # ──────────────────────────────────────────────
        # STEP 4: Register findings
        # ──────────────────────────────────────────────
        self._register_findings()

        if not self.results["acl_bypass_detected"]:
            print("  [+] ACL authorization verified. All publish attempts were properly restricted.")

        return self.results

    def _test_publish(self, port, publisher_user, publisher_pass, listener_user, listener_pass, topic):
        """
        Tests whether a publisher can send a message to a topic and a listener receives it.

        Uses a unique nonce in the payload to prevent false positives from other traffic.

        Returns:
            bool: True if the publish was received (ACL bypass), False if blocked.
        """
        unique_nonce = str(uuid.uuid4())
        test_payload = f'{{"audit": "mqtt-auditor", "nonce": "{unique_nonce}"}}'
        bypass_detected = False

        # --- Setup Listener ---
        try:
            listener = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
        except AttributeError:
            listener = mqtt.Client()

        if listener_user is not None:
            listener.username_pw_set(listener_user, listener_pass)

        def on_message(client, userdata, message):
            nonlocal bypass_detected
            payload_str = message.payload.decode("utf-8", errors="ignore")
            if unique_nonce in payload_str:
                bypass_detected = True
                pub_name = publisher_user if publisher_user else "anonymous"
                print(f"  [!] ACL BYPASS: '{pub_name}' published to '{message.topic}' without authorization!")

        listener.on_message = on_message

        try:
            listener.connect(self.target, port, keepalive=60)
            listener.loop_start()
            listener.subscribe(topic)
            time.sleep(0.5)  # Wait for subscription to register

            # --- Setup Publisher ---
            try:
                publisher = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
            except AttributeError:
                publisher = mqtt.Client()

            if publisher_user is not None:
                publisher.username_pw_set(publisher_user, publisher_pass)

            publisher.connect(self.target, port, keepalive=60)
            publisher.loop_start()
            publisher.publish(topic, test_payload, qos=0)
            time.sleep(1.5)  # Wait for message to be delivered

            publisher.loop_stop()
            publisher.disconnect()
            listener.loop_stop()
            listener.disconnect()

        except Exception as e:
            # Connection errors mean ACL or auth blocked us — not a bypass
            try:
                listener.loop_stop()
                listener.disconnect()
            except Exception:
                pass
            return False

        return bypass_detected

    def _register_findings(self):
        """Registers ACL bypass findings with the scorer."""
        for entry in self.results["unauthorized_publishes"]:
            user = entry["user"]
            topic = entry["topic"]
            port = entry["port"]

            self.scorer.add_finding(
                vulnerability_id="acl_bypass",
                details=(
                    f"Client '{user}' successfully published to restricted topic "
                    f"'{topic}' on port {port} without proper authorization. "
                    f"ACL rules are missing or misconfigured."
                ),
                severity="HIGH",
                evidence=(
                    f"Published test marker to {topic} without admin "
                    f"privileges using credentials: '{user}'."
                )
            )
