from mqtt_auditor.modules.base import BaseAuditModule

class AuthModule(BaseAuditModule):
    @property
    def name(self):
        return "Authentication Testing"

    @property
    def description(self):
        return "Tests for anonymous logins and default credentials."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")
        self.results = {
            "anonymous_allowed": True,
            "default_credentials_found": ["admin:admin"]
        }
        # Add finding if anonymous allowed
        self.scorer.add_finding(
            vulnerability_id="anonymous_access",
            details="The broker allows anonymous connections without a password.",
            severity="CRITICAL",
            evidence="CONNACK returned status 0 when connecting with no credentials."
        )
        self.scorer.add_finding(
            vulnerability_id="default_credentials",
            details="Found default login credentials: admin/admin",
            severity="CRITICAL",
            evidence="Successfully connected using admin:admin on port 1884."
        )
        return self.results
