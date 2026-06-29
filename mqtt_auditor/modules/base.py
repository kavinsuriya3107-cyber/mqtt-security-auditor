from abc import ABC, abstractmethod

class BaseAuditModule(ABC):
    def __init__(self, target, config, scorer):
        self.target = target
        self.config = config
        self.scorer = scorer
        self.results = {}

    @property
    @abstractmethod
    def name(self):
        """Returns the module's name."""
        pass

    @property
    @abstractmethod
    def description(self):
        """Returns the module's description."""
        pass

    @abstractmethod
    def run(self):
        """Executes the module audit logic."""
        pass
