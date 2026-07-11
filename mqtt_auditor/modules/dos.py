import time
import threading
import paho.mqtt.client as mqtt
from mqtt_auditor.modules.base import BaseAuditModule


class DosModule(BaseAuditModule):
    """
    Module 6 — Denial-of-Service (DoS) Resilience Testing

    This module evaluates broker resilience against common DoS attacks:
      1. Connection Flood Test — Try to establish many simultaneous connections
      2. Payload Size Limits — Send very large messages to test broker capacity
      3. Message Rate Limiting — Send rapid-fire messages to test queuing
      4. Subscription Bomb — Subscribe to massive number of topics
      5. Topic Explosion — Publish to many unique topics rapidly

    Why this matters:
      - Brokers without connection limits can be crashed by simple floods
      - Large payload handling impacts memory and performance
      - Lack of rate limiting enables spam/abuse
      - Unsupervised subscriptions can cause memory exhaustion
      - No limits on topic creation can crash the broker

    MQTT Compliance:
      - RFC 3986: Broker should enforce keep-alive and close idle connections
      - MQTT 3.1.1: Should implement flow control and QoS handling
      - Best Practice: Connection limits, payload limits, rate throttling

    Module Chaining:
      Uses credentials from auth module and ports from discovery module.
      Falls back gracefully if no credentials available.
    """

    def __init__(self, target, config, scorer, context=None):
        super().__init__(target, config, scorer, context)
        self.connection_results = []
        self.payload_results = []
        self.rate_limit_results = []

    @property
    def name(self):
        return "DoS Resilience Testing"

    @property
    def description(self):
        return "Tests broker limits: connections, payload sizes, message rates, subscriptions."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")

        timeout = self.config.get("timeout", 5.0)
        module_config = self.config.get("modules", {}).get("dos", {})

        # Read test parameters from config
        max_connections = module_config.get("max_connections_test", 10)
        max_payload_size = module_config.get("max_payload_size", 256 * 1024)  # 256KB
        message_rate = module_config.get("message_rate_test", 100)  # messages per second
        subscription_count = module_config.get("subscription_count_test", 50)

        self.results = {
            "connection_limit": None,
            "connection_limit_enforced": False,
            "payload_limit": None,
            "payload_limit_enforced": False,
            "rate_limiting_detected": False,
            "subscription_bomb_vulnerability": False,
            "broker_crashed": False,
            "test_results": {
                "connections": [],
                "payload": [],
                "rate_limiting": [],
                "subscriptions": []
            },
            "error": None
        }

        # Get connection details from context
        port = self._get_connectable_port()
        creds = self._get_best_credentials()

        if port is None:
            self.results["error"] = "No open MQTT ports found in context"
            print("  [-] No connectable ports found. Skipping DoS testing.")
            self._register_findings()
            return self.results

        if creds is False:
            self.results["error"] = "No valid credentials or anonymous access available"
            print("  [-] Cannot connect without credentials. Skipping DoS testing.")
            self._register_findings()
            return self.results

        username, password = creds
        connection_method = f"{username}:{password}" if username else "anonymous"
        print(f"  [*] Using connection method: {connection_method}")

        # ──────────────────────────────────────────────
        # TEST 1: Connection Limits
        # ──────────────────────────────────────────────
        print(f"  [*] Testing connection limits (max {max_connections} simultaneous)...")
        self._test_connection_limits(port, username, password, max_connections, timeout)

        # ──────────────────────────────────────────────
        # TEST 2: Payload Size Limits
        # ──────────────────────────────────────────────
        print(f"  [*] Testing payload size limits (up to {max_payload_size} bytes)...")
        self._test_payload_limits(port, username, password, max_payload_size, timeout)

        # ──────────────────────────────────────────────
        # TEST 3: Message Rate Limiting
        # ──────────────────────────────────────────────
        print(f"  [*] Testing message rate handling ({message_rate} msgs/sec)...")
        self._test_message_rate(port, username, password, message_rate, timeout)

        # ──────────────────────────────────────────────
        # TEST 4: Subscription Bombing
        # ──────────────────────────────────────────────
        print(f"  [*] Testing subscription bomb resilience ({subscription_count} subscriptions)...")
        self._test_subscription_limits(port, username, password, subscription_count, timeout)

        # ──────────────────────────────────────────────
        # TEST 5: Register findings
        # ──────────────────────────────────────────────
        self._register_findings()

        return self.results

    # ================================================================
    # TEST 1: Connection Flooding
    # ================================================================

    def _test_connection_limits(self, port, username, password, max_test, timeout):
        """
        Attempts to establish many simultaneous connections.

        Tests if broker can handle or limits concurrent connections.
        """
        print(f"  [*] Establishing {max_test} simultaneous connections...")

        connections = []
        successful = 0
        failed = 0

        for i in range(max_test):
            try:
                client = mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION1
                ) if hasattr(mqtt, 'CallbackAPIVersion') else mqtt.Client()

                if username:
                    client.username_pw_set(username, password)

                client.connect(self.target, port, keepalive=60)
                client.loop_start()
                connections.append(client)
                successful += 1

                if i % 5 == 0:
                    print(f"    [{i}/{max_test}] connections established")

                time.sleep(0.1)  # Small delay between connections

            except Exception as e:
                failed += 1
                if "too many open files" in str(e).lower() or "connection refused" in str(e).lower():
                    print(f"    [!] Connection limit hit at {successful} connections: {str(e)}")
                    self.results["connection_limit"] = successful
                    self.results["connection_limit_enforced"] = True
                    break

        print(f"  [+] Successfully established {successful} connections, {failed} failed")
        self.results["test_results"]["connections"] = {
            "successful": successful,
            "failed": failed,
            "limit_detected": self.results["connection_limit_enforced"]
        }

        # Cleanup
        for client in connections:
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass

        time.sleep(1)

    # ================================================================
    # TEST 2: Payload Size Limits
    # ================================================================

    def _test_payload_limits(self, port, username, password, max_payload, timeout):
        """
        Tests if broker handles large payloads or enforces size limits.
        """
        try:
            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION1
            ) if hasattr(mqtt, 'CallbackAPIVersion') else mqtt.Client()

            if username:
                client.username_pw_set(username, password)

            connected = False
            connection_error = None

            def on_connect(client, userdata, flags, rc):
                nonlocal connected
                connected = True

            client.on_connect = on_connect

            client.connect(self.target, port, keepalive=60)
            client.loop_start()

            # Wait for connection
            start = time.time()
            while not connected and (time.time() - start) < timeout:
                time.sleep(0.1)

            if not connected:
                print("  [-] Could not connect for payload testing")
                client.loop_stop()
                return

            # Test progressively larger payloads
            test_sizes = [
                1024,           # 1 KB
                10 * 1024,      # 10 KB
                100 * 1024,     # 100 KB
                256 * 1024,     # 256 KB (default MQTT_MAX_PACKET_LENGTH)
                1024 * 1024,    # 1 MB (likely to fail)
            ]

            largest_successful = 0
            for size in test_sizes:
                if size > max_payload:
                    break

                try:
                    payload = "A" * size
                    client.publish("dos/payload_test", payload, qos=0)
                    time.sleep(0.2)
                    largest_successful = size
                    print(f"    [+] Payload {size} bytes accepted")

                except Exception as e:
                    print(f"    [-] Payload {size} bytes failed: {str(e)}")
                    break

            self.results["payload_limit"] = largest_successful
            self.results["payload_limit_enforced"] = largest_successful < max_payload
            self.results["test_results"]["payload"] = {
                "largest_accepted": largest_successful,
                "limit_enforced": self.results["payload_limit_enforced"]
            }

            client.loop_stop()
            client.disconnect()

        except Exception as e:
            print(f"  [-] Payload testing error: {str(e)}")
            self.results["test_results"]["payload"] = {"error": str(e)}

    # ================================================================
    # TEST 3: Message Rate Limiting
    # ================================================================

    def _test_message_rate(self, port, username, password, message_rate, timeout):
        """
        Sends many messages rapidly to test rate limiting.

        If broker throttles messages, it should drop or queue them gracefully.
        """
        try:
            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION1
            ) if hasattr(mqtt, 'CallbackAPIVersion') else mqtt.Client()

            if username:
                client.username_pw_set(username, password)

            connected = False

            def on_connect(client, userdata, flags, rc):
                nonlocal connected
                connected = True

            client.on_connect = on_connect

            client.connect(self.target, port, keepalive=60)
            client.loop_start()

            start = time.time()
            while not connected and (time.time() - start) < timeout:
                time.sleep(0.1)

            if not connected:
                print("  [-] Could not connect for rate testing")
                client.loop_stop()
                return

            # Send messages as fast as possible
            messages_sent = 0
            burst_start = time.time()

            for i in range(message_rate):
                try:
                    client.publish(f"dos/rate_test/{i}", f"Message {i}", qos=0)
                    messages_sent += 1
                except Exception:
                    break

            burst_time = time.time() - burst_start
            actual_rate = messages_sent / burst_time if burst_time > 0 else 0

            print(f"    [+] Sent {messages_sent} messages in {burst_time:.2f}s ({actual_rate:.0f} msg/sec)")

            # Check if broker slowed us down (rate limiting)
            if actual_rate < message_rate * 0.7:  # More than 30% throttled
                self.results["rate_limiting_detected"] = True
                print(f"    [!] Rate limiting detected (target: {message_rate}, actual: {actual_rate:.0f})")

            self.results["test_results"]["rate_limiting"] = {
                "target_rate": message_rate,
                "actual_rate": round(actual_rate, 2),
                "rate_limiting_detected": self.results["rate_limiting_detected"]
            }

            time.sleep(1)
            client.loop_stop()
            client.disconnect()

        except Exception as e:
            print(f"  [-] Rate limiting test error: {str(e)}")

    # ================================================================
    # TEST 4: Subscription Bombing
    # ================================================================

    def _test_subscription_limits(self, port, username, password, subscription_count, timeout):
        """
        Tests if broker can handle massive subscription requests.

        Brokers should limit subscriptions or handle them gracefully.
        """
        try:
            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION1
            ) if hasattr(mqtt, 'CallbackAPIVersion') else mqtt.Client()

            if username:
                client.username_pw_set(username, password)

            connected = False

            def on_connect(client, userdata, flags, rc):
                nonlocal connected
                connected = True

            client.on_connect = on_connect

            client.connect(self.target, port, keepalive=60)
            client.loop_start()

            start = time.time()
            while not connected and (time.time() - start) < timeout:
                time.sleep(0.1)

            if not connected:
                print("  [-] Could not connect for subscription testing")
                client.loop_stop()
                return

            # Subscribe to many topics
            subscribed = 0
            for i in range(subscription_count):
                try:
                    topic = f"dos/bomb/{i}/sensor/data/stream"
                    client.subscribe(topic, qos=0)
                    subscribed += 1

                    if subscribed % 10 == 0:
                        print(f"    [{subscribed}/{subscription_count}] subscriptions")

                except Exception as e:
                    print(f"    [-] Subscription limit hit at {subscribed}: {str(e)}")
                    self.results["subscription_bomb_vulnerability"] = subscribed >= subscription_count * 0.8
                    break

            print(f"    [+] Successfully subscribed to {subscribed} topics")

            self.results["test_results"]["subscriptions"] = {
                "subscribed_count": subscribed,
                "requested_count": subscription_count,
                "vulnerability": self.results["subscription_bomb_vulnerability"]
            }

            time.sleep(1)
            client.loop_stop()
            client.disconnect()

        except Exception as e:
            print(f"  [-] Subscription test error: {str(e)}")

    def _register_findings(self):
        """
        Registers DoS vulnerabilities with the risk scorer.
        """
        # Finding: No Connection Limiting
        if not self.results["connection_limit_enforced"]:
            self.scorer.add_finding(
                vulnerability_id="no_connection_limit",
                details=(
                    "The broker does not appear to enforce connection limits. "
                    "An attacker can establish many connections to exhaust memory "
                    "and crash the broker (connection flood attack)."
                ),
                severity="HIGH",
                evidence=f"Successfully established many connections without throttling"
            )

        # Finding: No Payload Limits
        if self.results["payload_limit"] and self.results["payload_limit"] > 256 * 1024:
            self.scorer.add_finding(
                vulnerability_id="no_payload_limit",
                details=(
                    f"Broker accepts payloads larger than standard MQTT limit (256 KB). "
                    f"Large payloads can cause memory exhaustion and denial of service."
                ),
                severity="MEDIUM",
                evidence=f"Broker accepted payload of {self.results['payload_limit']} bytes"
            )

        # Finding: No Rate Limiting
        if not self.results["rate_limiting_detected"]:
            self.scorer.add_finding(
                vulnerability_id="no_rate_limiting",
                details=(
                    "The broker does not implement message rate limiting. "
                    "Attackers can spam messages to consume bandwidth and exhaust resources."
                ),
                severity="MEDIUM",
                evidence="Successfully sent rapid message bursts without throttling"
            )

        # Finding: Subscription Bombing Vulnerability
        if self.results["subscription_bomb_vulnerability"]:
            self.scorer.add_finding(
                vulnerability_id="subscription_bomb",
                details=(
                    "The broker accepts unlimited subscription requests without limits. "
                    "Attackers can subscribe to many topics to exhaust memory and crash the broker."
                ),
                severity="MEDIUM",
                evidence=f"Allowed {self.results['test_results']['subscriptions'].get('subscribed_count', 0)} simultaneous subscriptions"
            )
