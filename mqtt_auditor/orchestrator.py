import sys
from mqtt_auditor.scorer import RiskScorer
from mqtt_auditor.modules.discovery import DiscoveryModule
from mqtt_auditor.modules.auth import AuthModule
from mqtt_auditor.modules.topics import TopicsModule
from mqtt_auditor.modules.acl import AclModule
from mqtt_auditor.modules.tls_audit import TlsAuditModule
from mqtt_auditor.modules.dos import DosModule


class ScanOrchestrator:
    """
    The Orchestrator — Central brain of the MQTT Security Auditor.

    Responsibilities:
      1. Runs modules in a specific order (discovery → auth → topics → acl → tls → dos)
      2. Builds a shared 'context' dictionary from each module's results
      3. Passes that context to the next module so it can use previously discovered data
      4. Collects all findings and returns them to the CLI for display

    Module Chaining Data Flow:
      Discovery  →  open_ports, mqtt_confirmed, tls_available
      Auth       →  valid_credentials, anonymous_ports
      Topics     →  captured_topics, sys_data
      ACL        →  acl_bypass_detected
      TLS        →  tls_details (protocol, cipher, cert info)
      DoS        →  connection_limit, payload_limit
    """

    # Modules run in THIS specific order (dependencies flow downward)
    MODULE_ORDER = [
        ("discovery", DiscoveryModule),
        ("auth", AuthModule),
        ("topics", TopicsModule),
        ("acl", AclModule),
        ("tls_audit", TlsAuditModule),
        ("dos", DosModule),
    ]

    def __init__(self, target, config_manager):
        self.target = target
        self.config_manager = config_manager
        self.scorer = RiskScorer()
        self.results = {}
        self.context = {}  # Shared context passed between modules

    def run_scan(self):
        """Runs all enabled modules in order, chaining context between them."""
        print(f"[*] Starting scan against target: {self.target}")

        module_settings = self.config_manager.get("modules", {})

        for module_key, module_class in self.MODULE_ORDER:
            settings = module_settings.get(module_key, {})

            if not settings.get("enabled", False):
                print(f"[-] Skipping module {module_key} (disabled)")
                continue

            try:
                # Create module instance with shared context
                module_instance = module_class(
                    self.target,
                    self.config_manager,
                    self.scorer,
                    context=self.context  # Pass accumulated context
                )
                print(f"[+] Launching {module_instance.name}...")
                module_results = module_instance.run()
                self.results[module_key] = module_results

                # Extract key data from this module's results and merge into context
                self._update_context(module_key, module_results)

            except Exception as e:
                print(f"[-] Error running module {module_key}: {str(e)}", file=sys.stderr)

        print("[*] Scan completed. Evaluating findings...")
        return self.scorer.get_results()

    def _update_context(self, module_key, module_results):
        """
        Extracts important data from a module's results and adds it to the
        shared context so downstream modules can use it.

        This is the 'glue' that connects independent modules into a pipeline.
        """
        if module_results is None:
            return

        if module_key == "discovery":
            # Extract open ports list
            ports_dict = module_results.get("ports", {})
            self.context["open_ports"] = [
                int(p) for p, status in ports_dict.items() if status == "OPEN"
            ]
            self.context["mqtt_confirmed"] = module_results.get("mqtt_confirmed", False)
            self.context["tls_available"] = module_results.get("tls_available", False)
            self.context["tls_ports"] = module_results.get("tls_ports", [])
            self.context["connack_code"] = module_results.get("connack_code")

        elif module_key == "auth":
            # Extract valid credentials and anonymous access ports
            self.context["valid_credentials"] = module_results.get(
                "default_credentials_found", []
            )
            anonymous_allowed = module_results.get("anonymous_allowed", {})
            self.context["anonymous_ports"] = [
                int(p) for p, allowed in anonymous_allowed.items() if allowed
            ]

        elif module_key == "topics":
            # Extract discovered topics and $SYS data
            self.context["captured_topics"] = module_results.get("captured_topics", [])
            self.context["sys_data"] = module_results.get("sys_data", {})

        elif module_key == "tls_audit":
            self.context["tls_details"] = module_results
