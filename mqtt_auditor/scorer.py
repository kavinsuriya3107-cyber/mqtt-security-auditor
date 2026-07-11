class RiskScorer:
    """
    Risk Scoring Engine — Calculates an overall security risk score.

    Each vulnerability has a pre-assigned CVSS-like base score.
    The overall score is calculated using the highest individual score
    plus incremental adjustments for additional findings.

    Score Ranges:
      9.0 - 10.0  →  CRITICAL
      7.0 -  8.9  →  HIGH
      4.0 -  6.9  →  MEDIUM
      0.1 -  3.9  →  LOW
      0.0         →  INFORMATIONAL (no findings)
    """

    SEVERITY_SCORES = {
        # Authentication vulnerabilities
        "anonymous_access": 9.8,
        "default_credentials": 8.8,
        # Transport vulnerabilities
        "plaintext_transmission": 7.5,
        "no_tls": 8.0,
        "weak_tls_version": 6.5,
        "weak_cipher_suite": 5.5,
        "self_signed_certificate": 4.0,
        "expired_certificate": 7.0,
        "weak_tls_configuration": 5.9,
        # Topic & ACL vulnerabilities
        "wildcard_subscription": 8.6,
        "sys_topic_leak": 5.3,
        "acl_bypass": 8.6,
        # DoS vulnerabilities
        "no_connection_limit": 7.5,
        "no_payload_limit": 6.0,
        "no_rate_limiting": 5.5,
    }

    def __init__(self):
        self.findings = []

    def add_finding(self, vulnerability_id, details, severity="INFO", evidence=None):
        """Registers a new security finding."""
        score = self.SEVERITY_SCORES.get(vulnerability_id, 0.0)
        finding = {
            "id": vulnerability_id,
            "score": score,
            "severity": severity,
            "details": details,
            "evidence": evidence
        }
        self.findings.append(finding)

    def calculate_overall_score(self):
        """Calculates overall risk score from all registered findings."""
        if not self.findings:
            return 0.0
        max_score = max(f["score"] for f in self.findings)
        num_findings = len(self.findings)
        overall = min(10.0, max_score + (num_findings - 1) * 0.25)
        return round(overall, 1)

    def get_rating(self, score):
        """Maps a numeric score to a human-readable severity rating."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0.0:
            return "LOW"
        return "INFORMATIONAL"

    def get_results(self):
        """Returns the final scoring results dictionary."""
        overall_score = self.calculate_overall_score()
        return {
            "overall_score": overall_score,
            "rating": self.get_rating(overall_score),
            "findings": sorted(self.findings, key=lambda x: x["score"], reverse=True)
        }
