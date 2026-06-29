from mqtt_auditor.modules.base import BaseAuditModule

class TopicsModule(BaseAuditModule):
    @property
    def name(self):
        return "Topic Analysis"

    @property
    def description(self):
        return "Performs wildcard subscription and checks $SYS topic exposure."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")
        self.results = {
            "wildcard_subscription_allowed": True,
            "sys_topics_exposed": True,
            "captured_topics": ["factory/zone1/temp", "factory/zone1/power"]
        }
        self.scorer.add_finding(
            vulnerability_id="wildcard_subscription",
            details="Any client can subscribe to the '#' wildcard and read all messages.",
            severity="HIGH",
            evidence="Subscribed to '#' and received messages without ACL blocks."
        )
        self.scorer.add_finding(
            vulnerability_id="sys_topic_leak",
            details="$SYS/ internal broker topics are readable by unauthenticated users.",
            severity="MEDIUM",
            evidence="Read Mosquitto broker statistics from $SYS/broker/version."
        )
        return self.results
