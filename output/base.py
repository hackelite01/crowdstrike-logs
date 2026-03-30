from abc import ABC, abstractmethod
from typing import Any, Dict


class OutputHandler(ABC):
    name: str = "base"
    enabled: bool = True

    @abstractmethod
    def write(self, event: Dict[str, Any]) -> None:
        """Write a single event. Raise on unrecoverable error."""

    def close(self) -> None:
        """Optional cleanup on shutdown."""
