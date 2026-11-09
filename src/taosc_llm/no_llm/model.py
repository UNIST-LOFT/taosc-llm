"""Host-only, serializable contracts for bounded predicate synthesis."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math


@dataclass(frozen=True)
class SearchLimits:
    timeout: float = 3600.0
    max_evaluations: int = 256
    max_atoms: int = 512
    beam_width: int = 12
    max_clauses: int = 12
    max_factors: int = 6
    operand_depth: int = 2

    def __post_init__(self):
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)) or not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("timeout must be positive finite seconds")
        for name in ("max_evaluations", "max_atoms", "beam_width", "max_clauses", "max_factors", "operand_depth"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_atoms > 65536 or self.beam_width > 256:
            raise ValueError("max_atoms <= 65536 and beam_width <= 256 are required")
        if self.max_clauses > 128 or self.max_factors > 128 or self.operand_depth > 4:
            raise ValueError("max_clauses/max_factors <= 128 and operand_depth <= 4 are required")

    def to_dict(self) -> dict:
        return asdict(self)


class SearchStopped(Exception):
    """A planned search boundary, distinct from infrastructure failure."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason
