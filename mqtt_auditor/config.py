import os
import yaml

class ConfigManager:
    def __init__(self, config_path=None):
        self.config = {
            "timeout": 5.0,
            "max_connections": 50,
            "wordlist": "wordlists/mqtt_defaults.txt",
            "modules": {
                "discovery": {"enabled": True, "ports": [1883, 1884, 8883]},
                "auth": {"enabled": True},
                "topics": {"enabled": True, "capture_time": 5.0},
                "acl": {"enabled": True, "test_topic": "factory/zone2/cnc/cmd"},
                "tls_audit": {"enabled": True},
                "dos": {"enabled": False}
            }
        }
        if config_path:
            self.load_from_file(config_path)

    def load_from_file(self, config_path):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, "r") as f:
            file_config = yaml.safe_load(f)
            if file_config:
                self.merge_config(file_config)

    def merge_config(self, new_config):
        for key, val in new_config.items():
            if isinstance(val, dict) and key in self.config and isinstance(self.config[key], dict):
                self.config[key].update(val)
            else:
                self.config[key] = val

    def get(self, key, default=None):
        return self.config.get(key, default)
