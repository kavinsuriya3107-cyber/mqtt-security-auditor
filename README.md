# 🔒 MQTT Security Auditor

> An open-source CLI penetration testing tool that audits MQTT broker security configurations, finds vulnerabilities, proves they are exploitable, and generates professional security reports.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing only.** Only use it on MQTT brokers that you own or have explicit written permission to test. Unauthorized access to computer systems is illegal under the IT Act 2000 (India), CFAA (USA), and similar laws worldwide.

---

## 🎯 What It Does

MQTT Security Auditor scans a target MQTT broker and automatically checks for critical security misconfigurations:

| Module | Check | Status |
|:---|:---|:---|
| **Discovery** | Port scanning (1883/8883), banner grabbing | 🔄 In Progress |
| **Authentication** | Anonymous login, default credential brute-force | 🔜 Planned |
| **Topic Analysis** | Wildcard `#` subscription, `$SYS/#` exposure | 🔜 Planned |
| **ACL Verification** | Cross-topic publish/subscribe bypass | 🔜 Planned |
| **TLS/Crypto Audit** | TLS version, cipher suites, certificate validation | 🔜 Planned |
| **DoS Resilience** | Connection limits, payload size limits | 🔜 Planned |

---

## 🚀 Installation

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)
- A target MQTT broker (e.g., Mosquitto running locally)

### Install from source
```bash
git clone https://github.com/YOUR_USERNAME/mqtt-security-auditor.git
cd mqtt-security-auditor
pip install -e .
```

---

## 📖 Usage

### Basic scan
```bash
mqtt-auditor scan --target <BROKER_IP>
```

### Scan with custom config
```bash
mqtt-auditor scan --target <BROKER_IP> --config configs/default.yaml
```

### Example output
```
┌──────────────────────────────────────────┐
│ MQTT Security Auditor v1.0.0             │
│ Target: 192.168.1.100                    │
└──────────────────────────────────────────┘

[+] Port 1883: OPEN
[-] Port 8883: CLOSED

Audit Report Summary
Overall Risk Score: 9.2/10.0 (CRITICAL)

┌──────────┬──────────────────────┬──────────────────────┐
│ Severity │ Vulnerability ID     │ Description          │
├──────────┼──────────────────────┼──────────────────────┤
│ CRITICAL │ anonymous_access     │ Broker allows        │
│          │                      │ anonymous connections │
│ HIGH     │ plaintext_transmis.. │ Port 1883 open       │
│          │                      │ without encryption   │
└──────────┴──────────────────────┴──────────────────────┘

✔ Scan complete. HTML report saved to:
  file:///path/to/reports/report_192_168_1_100.html
```

---

## 🏗️ Architecture

```
mqtt-security-auditor/
├── mqtt_auditor/
│   ├── cli.py              # CLI entry point (click)
│   ├── orchestrator.py     # Runs modules & compiles results
│   ├── config.py           # YAML configuration loader
│   ├── scorer.py           # CVSS-like risk scoring engine
│   ├── reporter/
│   │   ├── html_report.py  # HTML report generator (Jinja2)
│   │   └── templates/
│   │       └── report.html # Report template
│   └── modules/
│       ├── base.py         # Abstract base class for modules
│       ├── discovery.py    # Port scanning & broker detection
│       ├── auth.py         # Authentication testing
│       ├── topics.py       # Topic enumeration & $SYS check
│       ├── acl.py          # ACL bypass verification
│       ├── tls_audit.py    # TLS/certificate auditing
│       └── dos.py          # DoS resilience testing
├── configs/
│   └── default.yaml        # Default scan configuration
├── wordlists/
│   └── mqtt_defaults.txt   # Default credential dictionary
└── docker/
    ├── docker-compose.yml  # Local test lab setup
    └── mosquitto.conf      # Broker configuration
```

### Data Flow
```
User Command → cli.py → orchestrator.py → [modules] → scorer.py → html_report.py → Browser Report
```

---

## 🧪 Setting Up a Local Test Lab

To safely test the tool, run a local Mosquitto broker:

### Option A: Native install (Kali Linux / Debian)
```bash
sudo apt update && sudo apt install mosquitto mosquitto-clients -y
sudo systemctl start mosquitto
mqtt-auditor scan --target localhost
```

### Option B: Docker
```bash
cd docker/
docker compose up -d
mqtt-auditor scan --target localhost
```

---

## 🛠️ Tech Stack

| Component | Technology | Purpose |
|:---|:---|:---|
| Language | Python 3.11+ | Core application logic |
| MQTT Client | paho-mqtt | Broker communication |
| CLI | click | Command-line interface |
| Terminal UI | rich | Colored terminal output |
| Reports | Jinja2 | HTML report generation |
| Config | PyYAML | Configuration management |
| TLS | ssl + cryptography | Certificate analysis |

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Kavinsuriya N G**
- 2nd Year B.E. EEE Student
- IoT Security & Application Security Enthusiast

---

## 🗺️ Roadmap

- [x] Project skeleton & CLI framework
- [x] HTML reporting engine
- [ ] Module 1: Real TCP port scanning & MQTT banner grabbing
- [ ] Module 2: Anonymous auth & credential brute-force
- [ ] Module 3: Wildcard topic capture & $SYS leak detection
- [ ] Module 4: ACL bypass verification
- [ ] Module 5: TLS/certificate auditing
- [ ] Module 6: DoS resilience testing
- [ ] JSON report export
- [ ] Professional documentation & GitHub release
