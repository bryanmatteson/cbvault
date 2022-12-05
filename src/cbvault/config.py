from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Config(BaseModel):
    address: str
    timeout: Optional[int] = None
    namespace: Optional[str] = None
    auth_method: str = "token"
    auth_params: Dict[str, Any] = Field(default_factory=dict)
    ignore_exceptions: bool = False
