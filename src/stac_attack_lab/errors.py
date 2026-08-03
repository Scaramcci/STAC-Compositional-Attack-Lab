class LabError(Exception):
    """Base project error."""


class ContractError(LabError):
    """Raised when a typed contract is invalid."""


class SafetyError(LabError):
    """Raised when a request violates the local safety boundary."""
