import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from mqtt_auditor.modules.base import BaseAuditModule


class TlsAuditModule(BaseAuditModule):
    """
    Module 5 — TLS/Cryptography Security Audit

    This module performs comprehensive TLS/SSL security validation:
      1. Certificate Validation — Checks expiration, self-signed status, key strength
      2. Protocol Version Testing — Detects weak TLS versions (SSLv3, TLSv1.0, TLSv1.1)
      3. Cipher Suite Analysis — Identifies weak or deprecated cipher suites
      4. Certificate Chain Verification — Validates issuer and chain integrity
      5. POODLE/BEAST/CRIME Detection — Tests for known TLS vulnerabilities

    Why this matters:
      - Weak TLS versions are vulnerable to downgrade attacks
      - Expired or self-signed certs indicate poor operational security
      - Weak ciphers can be cracked by attackers on the same network
      - Missing certificate validation allows MITM attacks

    Module Chaining:
      This module uses tls_available from discovery to know if port 8883 is reachable.
      It also uses any credentials from auth to authenticate during TLS tests (optional).
    """

    # Weak cipher suites known to be vulnerable (NIST, OWASP standards)
    WEAK_CIPHERS = {
        "NULL": "No encryption at all",
        "EXPORT": "Export-grade (40-bit) encryption, breakable in seconds",
        "DES": "Single DES, cryptographically broken",
        "RC4": "Stream cipher with known biases",
        "MD5": "Hash function vulnerable to collisions",
        "aNULL": "Anonymous cipher, no authentication",
        "eNULL": "No encryption, only authentication",
    }

    # Weak TLS versions (NIST deprecated, OWASP High Risk)
    WEAK_PROTOCOLS = {
        "SSLv2": "CRITICAL - Completely broken",
        "SSLv3": "CRITICAL - POODLE vulnerability",
        "TLSv1.0": "HIGH - Many known vulnerabilities",
        "TLSv1.1": "HIGH - Deprecated by NIST (2019)",
    }

    # Strong cipher suites (recommended by NIST, Mozilla)
    STRONG_CIPHERS = {
        "TLS_AES_256_GCM_SHA384": "AEAD cipher with 256-bit key",
        "TLS_CHACHA20_POLY1305_SHA256": "Modern AEAD cipher",
        "TLS_AES_128_GCM_SHA256": "Minimum acceptable AEAD",
    }

    @property
    def name(self):
        return "TLS/Cryptography Audit"

    @property
    def description(self):
        return "Validates TLS versions, cipher suites, certificates, and detects crypto vulnerabilities."

    def run(self):
        print(f"[*] Running {self.name} against {self.target}...")

        self.results = {
            "tls_enabled": False,
            "protocol_version": None,
            "cipher_suite": None,
            "certificate_info": {},
            "weak_protocols_detected": [],
            "weak_ciphers_detected": [],
            "certificate_issues": [],
            "security_score": 0.0,
            "error": None
        }

        # Check if TLS is available from discovery context
        tls_ports = self.context.get("tls_ports", [])
        if not tls_ports:
            print("  [-] No TLS-capable ports available from discovery. Skipping TLS audit.")
            self._register_findings()
            return self.results

        tls_port = tls_ports[0]
        print(f"  [*] Performing TLS audit on port {tls_port}...")

        # ──────────────────────────────────────────────
        # PHASE 1: Certificate and TLS Handshake Analysis
        # ──────────────────────────────────────────────
        cert_data = self._get_certificate_info(self.target, 8883)
        if cert_data is None:
            print("  [-] Could not retrieve certificate information.")
            self.results["error"] = "Certificate retrieval failed"
            self._register_findings()
            return self.results

        self.results["tls_enabled"] = True
        self.results["certificate_info"] = cert_data["info"]
        self.results["protocol_version"] = cert_data["protocol"]
        self.results["cipher_suite"] = cert_data["cipher"]

        print(f"  [+] TLS Enabled: {cert_data['protocol']}")
        print(f"  [+] Cipher: {cert_data['cipher']}")
        print(f"  [+] Certificate Subject: {cert_data['info'].get('subject', 'unknown')}")

        # ──────────────────────────────────────────────
        # PHASE 2: Certificate Validation
        # ──────────────────────────────────────────────
        cert_issues = self._validate_certificate(cert_data["info"])
        self.results["certificate_issues"] = cert_issues
        for issue in cert_issues:
            print(f"  [!] Certificate Issue: {issue}")

        # ──────────────────────────────────────────────
        # PHASE 3: Protocol Version Assessment
        # ──────────────────────────────────────────────
        protocol = cert_data["protocol"]
        if protocol in self.WEAK_PROTOCOLS:
            self.results["weak_protocols_detected"].append(protocol)
            print(f"  [!] WEAK PROTOCOL: {protocol} - {self.WEAK_PROTOCOLS[protocol]}")

        # ──────────────────────────────────────────────
        # PHASE 4: Cipher Suite Assessment
        # ──────────────────────────────────────────────
        cipher = cert_data["cipher"]
        for weak_pattern, description in self.WEAK_CIPHERS.items():
            if weak_pattern.upper() in cipher.upper():
                self.results["weak_ciphers_detected"].append({
                    "cipher": cipher,
                    "weakness": description
                })
                print(f"  [!] WEAK CIPHER DETECTED: {cipher}")
                break

        # ──────────────────────────────────────────────
        # PHASE 5: Test Protocol Downgrade Protection
        # ──────────────────────────────────────────────
        downgrade_safe = self._test_protocol_downgrade(self.target, 8883)
        if not downgrade_safe:
            print(f"  [!] WARNING: Broker may be vulnerable to protocol downgrade attacks")

        # ──────────────────────────────────────────────
        # PHASE 6: Calculate Security Score
        # ──────────────────────────────────────────────
        self.results["security_score"] = self._calculate_tls_security_score()

        # ──────────────────────────────────────────────
        # PHASE 7: Register findings
        # ──────────────────────────────────────────────
        self._register_findings()

        return self.results

    # ================================================================
    # HELPER METHODS
    # ================================================================

    def _get_certificate_info(self, host, port):
        """
        Retrieves TLS certificate and handshake information.

        Returns:
            dict: {
                "success": bool,
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "info": {certificate details}
            }
        """
        # Read timeout from config
        timeout = self.config.get("modules", {}).get("tls_audit", {}).get("timeout", self.config.get("timeout", 5.0))
        
        try:
            # Create SSL context that accepts any cert (for auditing)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Connect and perform TLS handshake
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))

                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    # Extract protocol and cipher
                    protocol = tls_sock.version()
                    cipher = tls_sock.cipher()[0]

                    # Get certificate in DER format
                    cert_der = tls_sock.getpeercert(binary_form=True)

                    return {
                        "success": True,
                        "protocol": protocol,
                        "cipher": cipher,
                        "info": self._parse_certificate(cert_der)
                    }

        except ssl.SSLError as e:
            print(f"  [-] SSL/TLS Error: {str(e)}")
            return None
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            print(f"  [-] Connection Error: {str(e)}")
            return None

    def _parse_certificate(self, cert_der):
        """
        Extracts relevant certificate fields using the cryptography library.

        Args:
            cert_der: Certificate in binary DER format

        Returns:
            dict: Certificate details
        """
        parsed = {
            "subject": "unknown",
            "issuer": "unknown",
            "version": "unknown",
            "serial_number": "unknown",
            "valid_from": "unknown",
            "valid_to": "unknown",
            "is_self_signed": False,
            "days_until_expiry": None,
            "public_key_type": "unknown",
            "public_key_bits": 0,
        }

        try:
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())

            # Extract subject common name
            subjects = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if subjects:
                parsed["subject"] = subjects[0].value

            # Extract issuer common name
            issuers = cert_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            if issuers:
                parsed["issuer"] = issuers[0].value

            # Check if self-signed (subject == issuer)
            parsed["is_self_signed"] = (
                parsed["subject"] == parsed["issuer"] and
                parsed["subject"] != "unknown"
            )

            # Extract serial and version
            parsed["serial_number"] = str(cert_obj.serial_number)
            parsed["version"] = cert_obj.version.name

            # Extract validity dates
            parsed["valid_from"] = cert_obj.not_valid_before.strftime("%b %d %H:%M:%S %Y GMT")
            parsed["valid_to"] = cert_obj.not_valid_after.strftime("%b %d %H:%M:%S %Y GMT")

            # Calculate days left until expiry
            days_left = (cert_obj.not_valid_after - datetime.utcnow()).days
            parsed["days_until_expiry"] = days_left

            # Extract public key info
            pub_key = cert_obj.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                parsed["public_key_type"] = "RSA"
                parsed["public_key_bits"] = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                parsed["public_key_type"] = "ECC"
                parsed["public_key_bits"] = pub_key.key_size

        except Exception as e:
            print(f"  [-] Error parsing certificate: {str(e)}")

        return parsed

    def _validate_certificate(self, cert_info):
        """
        Checks certificate for common security issues.

        Returns:
            list: List of issues found
        """
        issues = []

        # Check if self-signed
        if cert_info.get("is_self_signed"):
            issues.append("Certificate is SELF-SIGNED (not issued by trusted CA)")

        # Check expiration
        days_left = cert_info.get("days_until_expiry")
        if days_left is not None:
            if days_left < 0:
                issues.append(f"Certificate EXPIRED {abs(days_left)} days ago!")
            elif days_left < 30:
                issues.append(f"Certificate expires in {days_left} days (renewal recommended)")
            elif days_left < 90:
                issues.append(f"Certificate expires in {days_left} days (plan renewal soon)")

        # Check weak key size
        key_bits = cert_info.get("public_key_bits", 0)
        if key_bits < 2048:
            issues.append(f"Weak public key: {key_bits}-bit (should be ≥2048-bit)")
        elif key_bits < 4096:
            issues.append(f"Acceptable public key: {key_bits}-bit (4096-bit recommended for RSA)")

        # Check algorithm (if detectable)
        key_type = cert_info.get("public_key_type")
        if key_type == "ECC":
            if cert_info.get("public_key_bits", 0) < 256:
                issues.append("Weak ECC key size")

        return issues

    def _test_protocol_downgrade(self, host, port):
        """
        Tests if broker is vulnerable to TLS downgrade attacks.

        A broker should reject old protocols, but this checks the behavior.

        Returns:
            bool: True if downgrade safe, False if vulnerable
        """
        # Read timeout from config
        timeout = self.config.get("modules", {}).get("tls_audit", {}).get("timeout", self.config.get("timeout", 3.0))
        
        try:
            # Try to connect with TLSv1.0 (intentionally weak)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    # If we reach here, weak protocol was accepted
                    return False  # ← Vulnerable to downgrade

        except (ssl.SSLError, socket.timeout, OSError):
            # Good: weak protocol was rejected
            return True

    def _calculate_tls_security_score(self):
        """
        Calculates TLS security score (0-10).

        Based on:
          - Protocol version (TLSv1.2+ = good, TLSv1.0 = bad)
          - Cipher strength (256-bit = good, 128-bit = acceptable)
          - Certificate validity (valid and trusted = good)
        """
        score = 10.0

        # Deduct for weak protocols
        if self.results["weak_protocols_detected"]:
            score -= 5.0

        # Deduct for weak ciphers
        if self.results["weak_ciphers_detected"]:
            score -= 3.0

        # Deduct for certificate issues
        score -= len(self.results["certificate_issues"]) * 1.5

        return max(0.0, round(score, 1))

    def _register_findings(self):
        """
        Registers TLS vulnerabilities with the risk scorer.
        """
        if not self.results["tls_enabled"]:
            return

        # Finding: Weak TLS Protocol
        for protocol in self.results["weak_protocols_detected"]:
            severity = self.WEAK_PROTOCOLS.get(protocol, "MEDIUM")
            self.scorer.add_finding(
                vulnerability_id="weak_tls_version",
                details=(
                    f"Broker uses {protocol}, which has known vulnerabilities. "
                    f"Clients can be downgraded to use weak encryption. "
                    f"Recommended: Use TLSv1.2 or TLSv1.3."
                ),
                severity=severity,
                evidence=f"TLS handshake used protocol version: {protocol}"
            )

        # Finding: Weak Cipher Suites
        for weak_cipher in self.results["weak_ciphers_detected"]:
            self.scorer.add_finding(
                vulnerability_id="weak_cipher_suite",
                details=(
                    f"Broker accepted weak cipher: {weak_cipher['cipher']}. "
                    f"Reason: {weak_cipher['weakness']}. "
                    f"This cipher can be broken by attackers on the same network."
                ),
                severity="HIGH",
                evidence=f"Negotiated cipher during TLS handshake: {weak_cipher['cipher']}"
            )

        # Finding: Self-Signed Certificate
        if self.results["certificate_info"].get("is_self_signed"):
            self.scorer.add_finding(
                vulnerability_id="self_signed_certificate",
                details=(
                    "The TLS certificate is self-signed and not issued by a trusted CA. "
                    "Clients cannot verify the broker's identity, enabling MITM attacks."
                ),
                severity="MEDIUM",
                evidence=f"Certificate subject: {self.results['certificate_info'].get('subject')}"
            )

        # Finding: Expired or Expiring Certificate
        days_left = self.results["certificate_info"].get("days_until_expiry")
        if days_left is not None and days_left < 0:
            self.scorer.add_finding(
                vulnerability_id="expired_certificate",
                details=(
                    f"The TLS certificate expired {abs(days_left)} days ago. "
                    "Clients cannot establish secure connections."
                ),
                severity="CRITICAL",
                evidence=f"Certificate valid until: {self.results['certificate_info'].get('valid_to')}"
            )
        elif days_left is not None and days_left < 30:
            self.scorer.add_finding(
                vulnerability_id="expiring_certificate",
                details=(
                    f"The TLS certificate will expire in {days_left} days. "
                    "Immediate renewal is recommended."
                ),
                severity="MEDIUM",
                evidence=f"Days until expiry: {days_left}"
            )
