from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Base model for fail-closed project contracts."""

    model_config = ConfigDict(extra="forbid")
