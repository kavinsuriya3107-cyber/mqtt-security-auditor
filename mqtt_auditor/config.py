import os
import yaml


class ConfigManager:
    """
    Configuration Manager — Loads and merges scan settings.

    Configuration is resolved in this priority order (highest wins):
      1. Environment variables (MQTT_AUDITOR_TIMEOUT, MQTT_AUDITOR_WORDLIST)
      2. User-provided YAML config file (--config flag)
      3. Built-in defaults (hardcoded below)

    This ensures the tool works out-of-the-box with sensible defaults,
    but can be customized for any broker environment.
    """

    # Built-in defaults that work for most MQTT brokers
    DEFAULTS = {
        "timeout": 5.0,
        "max_connections": 50,
        "wordlist": "wordlists/mqtt_defaults.txt",
        "modules": {
            "discovery": {
                "enabled": True,
                "ports": [1883, 1884, 8883, 8884, 9001]
            },
            "auth": {
                "enabled": True
            },
            "topics": {
                "enabled": True,
                "capture_time": 5.0
            },
            "acl": {
                "enabled": True
            },
            "tls_audit": {
                "enabled": True
            },
            "dos": {
                "enabled": False  # Disabled by default — can disrupt production brokers
            }
        }
    }

    def __init__(self, config_path=None):
        # Start with a deep copy of defaults
        self.config = self._deep_copy(self.DEFAULTS)

        # Layer 2: Merge user YAML config if provided
        if config_path:
            self.load_from_file(config_path)

        # Layer 3: Apply environment variable overrides
        self._apply_env_overrides()

    def load_from_file(self, config_path):
        """Loads and merges a YAML configuration file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_path, "r") as f:
            file_config = yaml.safe_load(f)
            if file_config:
                self._deep_merge(self.config, file_config)

    def _deep_merge(self, base, override):
        """
        Recursively merges 'override' dict into 'base' dict.

        Unlike dict.update(), this preserves nested keys that are not
        explicitly overridden. For example, if the user's YAML only
        specifies 'modules.auth.enabled: false', all other module
        settings remain intact from defaults.
        """
        for key, value in override.items():
            if (
                key in base
                and isinstance(base[key], dict)
                and isinstance(value, dict)
            ):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _deep_copy(self, obj):
        """Creates a deep copy of nested dicts/lists without importing copy."""
        if isinstance(obj, dict):
            return {k: self._deep_copy(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._deep_copy(item) for item in obj]
        return obj

    def _apply_env_overrides(self):
        """
        Checks for environment variables that override config values.

        Supported variables:
          MQTT_AUDITOR_TIMEOUT   → overrides 'timeout'
          MQTT_AUDITOR_WORDLIST  → overrides 'wordlist'
          MQTT_AUDITOR_PORTS     → overrides 'modules.discovery.ports' (comma-separated)
        """
        env_timeout = os.environ.get("MQTT_AUDITOR_TIMEOUT")
        if env_timeout:
            try:
                self.config["timeout"] = float(env_timeout)
            except ValueError:
                pass

        env_wordlist = os.environ.get("MQTT_AUDITOR_WORDLIST")
        if env_wordlist:
            self.config["wordlist"] = env_wordlist

        env_ports = os.environ.get("MQTT_AUDITOR_PORTS")
        if env_ports:
            try:
                ports = [int(p.strip()) for p in env_ports.split(",")]
                self.config["modules"]["discovery"]["ports"] = ports
            except ValueError:
                pass

    def get(self, key, default=None):
        """Returns a top-level config value."""
        return self.config.get(key, default)
