class RiskScorer:
    # CVSS-like scores for individual vulnerabilities
    SEVERITY_SCORES = {
        "anonymous_access": 9.8,
        "default_credentials": 8.8,
        "plaintext_transmission": 7.5,
        "wildcard_subscription": 8.6,
        "sys_topic_leak": 5.3,
        "acl_bypass": 8.6,
        "no_connection_limit": 7.5,
        "weak_tls_configuration": 5.9,
    }

    def __init__(self):
        self.findings = []

    def add_finding(self, vulnerability_id, details, severity="INFO", evidence=None):
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
        if not self.findings:
            return 0.0
        # Formula: overall score is dominated by the highest score,
        # with small increases for each additional finding.
        max_score = max(f["score"] for f in self.findings)
        num_findings = len(self.findings)
        
        # Max score is 10.0
        overall = min(10.0, max_score + (num_findings - 1) * 0.25)
        return round(overall, 1)

    def get_rating(self, score):
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
        overall_score = self.calculate_overall_score()
        return {
            "overall_score": overall_score,
            "rating": self.get_rating(overall_score),
            "findings": sorted(self.findings, key=lambda x: x["score"], reverse=True)
        }
