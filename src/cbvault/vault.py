from __future__ import annotations, unicode_literals

import os
from typing import Any, Dict, Optional, Tuple, Union, overload

from cbasyncio import AsyncerContextManager

from ._auth import get_auth
from ._client import AuthKind, Client, Record
from ._utils import format_url
from .config import Config

import logging

logger = logging.getLogger("cbvault")


class Vault:
    @overload
    def __init__(
        self,
        address: Optional[str] = ...,
        *,
        timeout: Optional[int] = ...,
        namespace: Optional[str] = ...,
        auth_method: AuthKind = ...,
        auth_params: Dict[str, Any] = ...,
        ignore_exceptions: bool = ...,
    ) -> None:
        ...

    @overload
    def __init__(self, config: Config, /) -> None:
        ...

    def __init__(
        self,
        address: Union[str, Config, None] = None,
        *,
        timeout: Optional[int] = None,
        namespace: Optional[str] = None,
        auth_method: AuthKind = "token",
        auth_params: Dict[str, Any] = {},
        ignore_exceptions: bool = False,
    ) -> None:
        if address is None or isinstance(address, str):
            config = Config(
                address=address or os.getenv("VAULT_ADDR", "http://localhost:8200"),
                timeout=timeout,
                namespace=namespace,
                auth_method=auth_method,
                auth_params=auth_params,
                ignore_exceptions=ignore_exceptions,
            )
        else:
            config = address

        client = Client(
            address=config.address.rstrip("/") + "/v1",
            timeout=config.timeout,
            ignore_exceptions=config.ignore_exceptions,
            namespace=config.namespace,
            auth=get_auth(config),
        )
        self._client = client

    def read_secret(self, path: str) -> Record:
        if path.startswith("/"):
            path = path[1:]

        api_path = format_url("/{path}", path=path)
        logger.debug("Reading secret at %s", api_path)

        response = self._client.get(url=api_path)
        return response.record

    def read_credentials(self, mount_point: str, name: str) -> Record:
        if mount_point.startswith("/"):
            mount_point = mount_point[1:]

        api_path = format_url("/{}/creds/{}", mount_point, name)
        logger.debug("Reading credentials at %s", api_path)

        response = self._client.get(url=api_path)
        return response.record

    def __enter__(self) -> Vault:
        self._client.__enter__()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self._client.__exit__(*exc_info)

    def close(self) -> None:
        self._client.close()


class AsyncVault(AsyncerContextManager[Vault]):
    @overload
    def __init__(
        self,
        address: Optional[str] = ...,
        /,
        *,
        timeout: Optional[int] = ...,
        namespace: Optional[str] = ...,
        auth_method: AuthKind = ...,
        auth_params: Dict[str, Any] = ...,
        ignore_exceptions: bool = ...,
    ) -> None:
        ...

    @overload
    def __init__(self, config: Config, /) -> None:
        ...

    @overload
    def __init__(self, vault: Vault, /) -> None:
        ...

    def __init__(
        self,
        vault: Union[Config, Vault, str, None] = None,
        /,
        **kwargs: Any,
    ) -> None:
        if not isinstance(vault, Vault):
            vault = Vault(vault, **kwargs)
        super().__init__(vault)

    async def read_secret(self, path: str) -> Record:
        return await self.run_sync(self.raw.read_secret, path)

    async def read_credentials(self, mount_point: str, name: str) -> Record:
        return await self.run_sync(self.raw.read_credentials, mount_point, name)


def get_secret(
    path: str,
    config: Optional[Config] = None,
    *,
    address: Optional[str] = None,
    timeout: Optional[int] = None,
    namespace: Optional[str] = None,
    auth_method: Optional[str] = None,
    auth_params: Dict[str, Any] = {},
    ignore_exceptions: bool = False,
) -> Tuple[Dict[str, Any], Optional[int]]:
    config = config or Config(
        address=address or os.getenv("VAULT_ADDR", "http://localhost:8200"),
        timeout=timeout,
        auth_method=auth_method or "token",
        auth_params=auth_params,
        ignore_exceptions=ignore_exceptions,
        namespace=namespace,
    )
    with Vault(config) as vault:
        return vault.read_secret(path).get_data_with_ttl()
