from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Literal, Optional, Tuple, Union
from uuid import UUID

import httpx
from pydantic import BaseModel, Field, PrivateAttr, validator

from ._utils import normalize_path, raise_for_error

AuthKind = Literal["aws", "token"]
SecretKind = Literal["kv", "kv2", "pki", "consul"]


class AuthResult(BaseModel):
    client_token: str
    accessor: str
    policies: List[str] = Field(default_factory=list)
    token_policies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    lease_duration: int
    renewable: bool
    entity_id: UUID
    token_type: str
    orphan: bool

    def get_token_with_expiry(self) -> Tuple[str, Optional[datetime]]:
        return self.client_token, datetime.utcnow() + timedelta(seconds=self.lease_duration)

    def get_token_with_ttl(self) -> Tuple[str, Optional[int]]:
        return self.client_token, self.lease_duration if self.lease_duration > 0 else None


class Record(BaseModel):
    request_id: UUID
    lease_id: Union[str, UUID]
    renewable: bool
    lease_duration: int
    auth: Optional[AuthResult] = None
    data: Dict[str, Any] = Field(default_factory=dict)

    def get_data(self) -> Dict[str, Any]:
        return self.data or {}

    def get_data_with_expiry(self) -> Tuple[Dict[str, Any], Optional[datetime]]:
        return self.data or {}, datetime.utcnow() + timedelta(seconds=self.lease_duration)

    def get_data_with_ttl(self) -> Tuple[Dict[str, Any], Optional[int]]:
        return self.data or {}, self.lease_duration if self.lease_duration > 0 else None

    @validator("data", pre=True)
    def _validate_data(cls, v: Any) -> Dict[str, Any]:
        return v or {}


class Request(BaseModel):
    method: str
    url: str
    headers: Dict[str, Any] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    content: bytes = b""


class Response(BaseModel):
    method: str
    url: str
    status: int
    content: Union[bytes, str, Dict[str, Any]]
    headers: Dict[str, str] = Field(default_factory=dict)

    _record: Optional[Record] = PrivateAttr(None)

    @property
    def record(self) -> Record:
        if self._record is None:
            if isinstance(self.content, (str, bytes)):
                self._record = Record.parse_raw(self.content)
            else:
                assert isinstance(self.content, dict), "Response content must be a dict, str, bytes"
                self._record = Record.parse_obj(self.content)
        return self._record

    @property
    def data(self) -> Dict[str, Any]:
        return self.record.data or {}

    @property
    def auth(self) -> Optional[AuthResult]:
        return self.record.auth


class Client:
    _session: Optional[httpx.Client]
    _base_url: str
    _timeout: Optional[int]
    _headers: Dict[str, Any]
    _auth: Optional[httpx.Auth]
    _ignore_exceptions: bool

    def __init__(
        self,
        address: str,
        auth: Optional[httpx.Auth] = None,
        timeout: Optional[int] = None,
        namespace: Optional[str] = None,
        ignore_exceptions: bool = False,
    ) -> None:
        self._auth = auth
        self._ignore_exceptions = ignore_exceptions
        self._session = None
        self._timeout = timeout
        self._base_url = address
        self._headers = {"X-Vault-Request": "true"}
        if namespace:
            self._headers["X-Vault-Namespace"] = namespace

    @property
    def session(self) -> httpx.Client:
        if not self._session:
            self._session = httpx.Client(
                base_url=self._base_url,
                timeout=self._timeout,
                headers=self._headers.copy(),
                auth=self._auth,
            )
        return self._session

    def __enter__(self) -> Client:
        self.session.__enter__()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.session.__exit__(*exc_info)
        self._session = None

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("get", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("post", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Response:
        return self.request("put", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.request("delete", url, **kwargs)

    def list(self, url: str, params: Dict[str, Any] = {}, **kwargs: Any) -> Response:
        params["list"] = True
        return self.request("get", url, params=params, **kwargs)

    def request(
        self,
        method: str,
        path: str,
        headers: Dict[str, Any] = {},
        params: Dict[str, Any] = {},
        raise_exception: bool = True,
        **kwargs: Any,
    ) -> Response:
        path = normalize_path(path)
        req = self.session.build_request(method, path, headers=headers, params=params, **kwargs)  # type: ignore
        response = self.session.send(req)

        content: Union[str, Dict[str, Any]]
        if response.headers.get("Content-Type") == "application/json":
            content = response.json()
        else:
            content = response.text

        if not response.is_success and (raise_exception and not self._ignore_exceptions):
            if isinstance(content, dict):
                message = ", ".join(content.get("errors") or [])
            else:
                message = content

            raise_for_error(method, path, response.status_code, message)

        return Response(
            method=method,
            url=path,
            status=response.status_code,
            content=content,
            headers=dict(response.headers.items()),
        )
