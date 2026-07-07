from abc import ABC, abstractmethod


class BaseAuditModule(ABC):
    """
    Abstract Base Class for all audit modules.

    Every security audit module (discovery, auth, topics, acl, tls, dos)
    inherits from this class.

    Args:
        target: The IP address or hostname of the MQTT broker being audited.
        config: The ConfigManager instance containing scan settings from YAML.
        scorer: The RiskScorer instance to register vulnerability findings.
        context: A shared dictionary containing results from previously-run modules.
                 This enables module chaining — e.g., the auth module discovers
                 valid credentials, and the topics module uses them to connect.

    Context Keys (populated by the orchestrator as modules complete):
        context['open_ports']       → list of open port numbers (from discovery)
        context['mqtt_confirmed']   → bool, True if MQTT protocol was verified
        context['valid_credentials'] → list of dicts with 'username', 'password', 'port'
        context['anonymous_ports']  → list of ports allowing anonymous access
        context['captured_topics']  → list of topic strings discovered (from topics)
        context['tls_available']    → bool, True if TLS handshake succeeded on 8883
    """

    def __init__(self, target, config, scorer, context=None):
        self.target = target
        self.config = config
        self.scorer = scorer
        self.context = context if context is not None else {}
        self.results = {}

    @property
    @abstractmethod
    def name(self):
        """Returns the module's human-readable name."""
        pass

    @property
    @abstractmethod
    def description(self):
        """Returns a short description of the module's purpose."""
        pass

    @abstractmethod
    def run(self):
        """Executes the module's audit logic and returns a results dictionary."""
        pass

    def _get_best_credentials(self):
        """
        Helper method to retrieve the best available credentials from context.

        Priority:
          1. Valid credentials discovered by the auth module
          2. Anonymous access (no credentials needed)
          3. None (cannot connect)

        Returns:
            tuple: (username, password) or (None, None) for anonymous,
                   or False if no connection method is available.
        """
        # Check if anonymous access is available on any port
        anonymous_ports = self.context.get("anonymous_ports", [])
        if anonymous_ports:
            return (None, None)

        # Check if auth module found valid credentials
        valid_creds = self.context.get("valid_credentials", [])
        if valid_creds:
            # Return the first valid credential pair
            cred = valid_creds[0]
            return (cred["username"], cred["password"])

        # No way to connect
        return False

    def _get_connectable_port(self):
        """
        Returns the best port to connect to for MQTT communication.

        Priority:
          1. Ports with anonymous access
          2. Ports with discovered credentials
          3. First open MQTT port

        Returns:
            int: Port number, or None if no port is available.
        """
        anonymous_ports = self.context.get("anonymous_ports", [])
        if anonymous_ports:
            return anonymous_ports[0]

        valid_creds = self.context.get("valid_credentials", [])
        if valid_creds:
            return valid_creds[0]["port"]

        open_ports = self.context.get("open_ports", [])
        if open_ports:
            return open_ports[0]

        return None
