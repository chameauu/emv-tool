"""
Core validator types: ValidationError and ValidationResult.

Separated from __init__.py to avoid circular imports with individual validators.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ValidationError:
    """A single validation issue (error or warning)."""
    code: str
    message: str
    position: Optional[int] = None
    severity: str = "error"  # "error" or "warning"

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "position": self.position,
            "severity": self.severity,
        }


@dataclass
class ValidationResult:
    """Result of a validation operation."""
    valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)
    cleaned_hex: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
            "cleaned_hex": self.cleaned_hex,
            "metadata": self.metadata,
        }