import os
from typing import Any, Callable, Dict, Iterable, List, Optional, Union

import dpath.util
from pydantic import BaseModel
from pydantic.fields import ModelField
from pydantic.utils import deep_update

from .config import Config
from .vault import Vault


class VaultSource:
    config: Config
    paths: List[str]
    case_sensitive: bool

    def __init__(
        self,
        *,
        case_sensitive: bool = False,
        vault_address: Optional[str] = None,
        vault_auth_method: Optional[str] = None,
        vault_auth_params: Optional[Dict[str, Any]] = None,
        vault_timeout: Optional[int] = None,
        vault_config: Optional[Config] = None,
        vault_path: Union[str, Iterable[str], None] = None,
    ) -> None:
        self.case_sensitive = case_sensitive
        self.config = vault_config or Config(
            address=vault_address or os.getenv("VAULT_ADDR", "http://localhost:8200"),
            timeout=vault_timeout,
            auth_method=vault_auth_method or "token",
            auth_params=vault_auth_params or {},
        )
        self.paths = [vault_path] if isinstance(vault_path, str) else list(vault_path or [])

    def __call__(self, model: BaseModel) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if not self.paths:
            return result

        def xform(value: str) -> str:
            return value if self.case_sensitive else value.lower()

        with Vault(self.config) as vault:
            secret = deep_update(*(vault.read_secret(path).data for path in self.paths))

        for field in model.__fields__.values():
            for name in map(xform, _get_source_names(field, "vault")):
                if value := dpath.util.get(secret, name, "/", None):  # type: ignore
                    result[field.alias] = value
                    break

        return result

    def __repr__(self) -> str:
        return f"VaultSource(path={self.paths!r}, config={self.config!r}"


def _get_source_names(field: ModelField, extra: str, *, transform: Optional[Callable[[str], str]] = None) -> List[str]:
    source_names: Union[str, Iterable[str]] = field.field_info.extra.get(extra, field.name)
    if isinstance(source_names, str):
        source_names = [source_names]
    else:
        source_names = list(source_names)
    if transform is not None:
        source_names = [transform(name) for name in source_names]
    return source_names
