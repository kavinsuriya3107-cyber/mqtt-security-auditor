# 🔒 MQTT Security Auditor

MQTT Security Auditor is a Python-based CLI security auditing tool designed to assess the security posture of MQTT brokers. It helps security researchers, IoT developers, and system administrators identify common misconfigurations such as anonymous access, weak authentication, plaintext exposure, topic leakage, insecure TLS usage, and weak resilience against abusive connection patterns.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)

---

## ⚠️ Disclaimer

This tool is intended only for authorized security testing. Use it only against MQTT brokers that you own or have explicit written permission to test. Unauthorized access to systems is illegal and may violate local and international laws.

---

## 🎯 Problem It Solves

MQTT is widely used in IoT and industrial systems, but many brokers are deployed with weak security defaults. This project helps uncover issues such as:

- Open MQTT services exposed to the network
- Anonymous or unrestricted broker access
- Weak default credentials
- Topic exposure through wildcard subscriptions
- Insecure or poorly configured TLS settings
- Poor resistance to abusive connection behavior

The goal is to provide a practical, extensible auditing workflow that produces actionable findings and a professional report.

---

## ✅ What the Tool Does

The current version of the auditor performs an end-to-end scan that includes:

- Broker discovery and MQTT service detection
- Port probing for common MQTT endpoints
- Authentication testing for anonymous access and default credentials
- Topic analysis for wildcard and `$SYS` exposure
- ACL-related checks for publish/subscribe isolation issues
- TLS and certificate-oriented auditing
- DoS resilience checks for connection and payload-based abuse scenarios
- HTML report generation for human-readable results

---

## 🧩 Core Features

- CLI-driven scanning with a simple command interface
- Modular architecture for easy extension
- Shared context pipeline between modules
- Configurable scan profiles via YAML
- Risk scoring for prioritizing results
- Professional HTML report generation
- Local lab support with Docker and Mosquitto

---

## 🚀 Installation

### Prerequisites
- Python 3.11+
- pip
- A target MQTT broker for testing

### Install from source

```bash
git clone https://github.com/kavinsuriya3107-cyber/mqtt-security-auditor.git
cd mqtt-security-auditor
pip install -e .
```

---

## 📖 How to Use It

### Basic scan

```bash
mqtt-auditor scan --target <BROKER_IP_OR_HOST>
```

### Scan with a custom configuration profile

```bash
mqtt-auditor scan --target <BROKER_IP_OR_HOST> --config configs/default.yaml
```

### Example output

```text
MQTT Security Auditor v1.0.0
Target: 192.168.1.100

[+] Discovery completed
[+] Authentication checks completed
[+] Topic leakage checks completed
[+] TLS audit completed

Overall Risk Score: 8.7/10.0 (HIGH)
```

The tool will also generate an HTML report and save it in the reports directory.

---

## 🏗️ Architecture Overview

The project is organized around a modular pipeline:

```text
User Input → CLI → Orchestrator → Modules → Scorer → Reporter
```

### Repository Structure

```text
mqtt-security-auditor/
├── mqtt_auditor/
│   ├── cli.py                  # Command-line entry point
│   ├── config.py               # YAML configuration loading
│   ├── orchestrator.py         # Runs modules and chains context
│   ├── scorer.py               # Risk scoring and result aggregation
│   ├── modules/
│   │   ├── base.py             # Shared module interface
│   │   ├── discovery.py        # Port scanning and MQTT detection
│   │   ├── auth.py             # Anonymous/default credential checks
│   │   ├── topics.py           # Topic exposure analysis
│   │   ├── acl.py              # ACL-related checks
│   │   ├── tls_audit.py        # TLS and certificate assessment
│   │   └── dos.py              # DoS resilience tests
│   └── reporter/
│       ├── html_report.py      # HTML report generator
│       └── templates/
│           └── report.html      # Report template
├── configs/
│   └── default.yaml            # Default scan configuration
├── docker/
│   ├── docker-compose.yml
│   ├── mosquitto.conf
│   ├── aclfile
│   └── config_dir/
├── wordlists/
│   └── mqtt_defaults.txt
└── requirements.txt
```

---

## ⚙️ Configuration

The default configuration is located in [configs/default.yaml](configs/default.yaml). It controls:

- Enabled modules
- Timeout values
- Port sets to scan
- Credential wordlist paths
- Maximum connection settings for DoS-related tests

You can customize the behavior by creating your own YAML file and passing it using the `--config` option.

---

## 🧪 Local Test Lab

A local Mosquitto-based environment is included for safe testing.

### Docker-based setup

```bash
cd docker/
docker compose up -d
mqtt-auditor scan --target localhost
```

### Native Linux setup

```bash
sudo apt update && sudo apt install mosquitto mosquitto-clients -y
sudo systemctl start mosquitto
mqtt-auditor scan --target localhost
```

---

## 🛠️ Technology Stack

| Component | Technology |
|:---|:---|
| Language | Python 3.11+ |
| MQTT Communication | paho-mqtt |
| CLI | click |
| Terminal UI | rich |
| Report Generation | Jinja2 |
| Configuration | PyYAML |
| TLS Handling | ssl, cryptography |

---

## 📦 Suggested Commit Plan

Below is a professional commit structure for the repository so the project history stays clean and meaningful.

| File | Purpose | Recommended Commit Title |
|:---|:---|:---|
| README.md | Project documentation and usage guide | docs: create professional project README |
| setup.py | Package metadata and console entry point | build: add package setup and CLI entry point |
| requirements.txt | Runtime dependencies | deps: add required Python packages |
| mqtt_auditor/cli.py | CLI interface | feat: implement MQTT auditor command-line interface |
| mqtt_auditor/config.py | YAML-based configuration loading | feat: add configurable scan profiles |
| mqtt_auditor/orchestrator.py | End-to-end scan orchestration | feat: implement scanning pipeline and module chaining |
| mqtt_auditor/scorer.py | Risk evaluation and scoring | feat: add risk scoring and result aggregation |
| mqtt_auditor/modules/base.py | Shared module abstraction | feat: introduce shared audit module base class |
| mqtt_auditor/modules/discovery.py | Port scanning and MQTT detection | feat: implement broker discovery and service detection |
| mqtt_auditor/modules/auth.py | Authentication and credential checks | feat: add authentication and default credential testing |
| mqtt_auditor/modules/topics.py | Topic exposure analysis | feat: add topic discovery and $SYS analysis |
| mqtt_auditor/modules/acl.py | ACL-related security checks | feat: implement ACL bypass and isolation checks |
| mqtt_auditor/modules/tls_audit.py | TLS and certificate auditing | feat: add TLS handshake and certificate assessment |
| mqtt_auditor/modules/dos.py | DoS resilience testing | feat: add DoS and abuse-resilience checks |
| mqtt_auditor/reporter/html_report.py | HTML report generation | feat: generate professional HTML audit reports |
| mqtt_auditor/reporter/templates/report.html | Report styling and presentation | ui: add HTML report template |
| configs/default.yaml | Default scan profile | config: add default MQTT audit configuration |
| docker/docker-compose.yml | Local broker test environment | devops: add Docker-based Mosquitto test environment |
| docker/mosquitto.conf | Broker configuration for lab testing | config: add Mosquitto test broker settings |
| docker/aclfile | ACL rules for local testing | config: add ACL rules for local broker testing |
| docker/config_dir/pwfile | Test credentials for local broker | config: add test user credentials for lab environment |
| wordlists/mqtt_defaults.txt | Default credential dictionary | data: add MQTT default credential wordlist |

### Recommended final release commit

- release: prepare v1.0.0 of MQTT Security Auditor

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 👤 Author

Kavinsuriya N G

IoT Security and Application Security enthusiast focused on building practical security tooling for connected systems.

