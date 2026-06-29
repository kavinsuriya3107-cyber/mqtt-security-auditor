import sys
from mqtt_auditor.scorer import RiskScorer
from mqtt_auditor.modules.discovery import DiscoveryModule
from mqtt_auditor.modules.auth import AuthModule
from mqtt_auditor.modules.topics import TopicsModule
from mqtt_auditor.modules.acl import AclModule
from mqtt_auditor.modules.tls_audit import TlsAuditModule
from mqtt_auditor.modules.dos import DosModule

class ScanOrchestrator:
    MODULE_MAP = {
        "discovery": DiscoveryModule,
        "auth": AuthModule,
        "topics": TopicsModule,
        "acl": AclModule,
        "tls_audit": TlsAuditModule,
        "dos": DosModule
    }

    def __init__(self, target, config_manager):
        self.target = target
        self.config_manager = config_manager
        self.scorer = RiskScorer()
        self.results = {}

    def run_scan(self):
        print(f"[*] Starting scan against target: {self.target}")
        
        module_settings = self.config_manager.get("modules", {})
        
        for module_key, module_class in self.MODULE_MAP.items():
            settings = module_settings.get(module_key, {})
            if settings.get("enabled", False):
                try:
                    module_instance = module_class(
                        self.target, 
                        self.config_manager, 
                        self.scorer
                    )
                    print(f"[+] Launching {module_instance.name}...")
                    self.results[module_key] = module_instance.run()
                except Exception as e:
                    print(f"[-] Error running module {module_key}: {str(e)}", file=sys.stderr)
            else:
                print(f"[-] Skipping module {module_key} (disabled)")
        
        print("[*] Scan completed. Evaluating findings...")
        return self.scorer.get_results()
