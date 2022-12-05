import hmac
import json
import os
from base64 import b64encode
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, Optional, Tuple, cast
from urllib.parse import parse_qsl, urlencode
import cbasyncio

import logging


import httpx

from .config import Config

METADATA_BASE_URL = "http://169.254.169.254"
METADATA_BASE_URL_IPv6 = "http://[fd00:ec2::254]"

logger = logging.getLogger("cbvault")


def get_auth(config: "Config") -> httpx.Auth:
    params = config.auth_params.copy()
    if config.auth_method == "aws":
        return AwsAuth(config, **params)
    elif config.auth_method == "token":
        return TokenAuth(token=params.get("token", None))
    else:
        raise ValueError(f"Unknown auth kind: {config.auth_method}")


def get_token_from_env() -> Optional[str]:
    token = os.getenv("VAULT_TOKEN")
    if not token:
        token_file_path = os.path.expanduser("~/.vault-token")
        if os.path.exists(token_file_path):
            with open(token_file_path, "r") as f_in:
                token = f_in.read().strip()

    return token


class TokenAuth(httpx.Auth):
    def __init__(self, token: Optional[str]) -> None:
        self.token = token or get_token_from_env()

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self.token:
            request.headers["X-Vault-Token"] = self.token
        yield request


class AwsAuth(httpx.Auth):
    access_key: Optional[str]
    secret_key: Optional[str]
    session_token: Optional[str]
    imds_creds_expiration: Optional[datetime]
    region: str
    server_id: Optional[str]
    role: Optional[str]
    mount_point: str
    token: str
    expires: Optional[datetime]

    def __init__(
        self,
        config: "Config",
        *,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        region: Optional[str] = None,
        server_id: Optional[str] = None,
        role: Optional[str] = None,
        mount_point: str = "aws",
    ) -> None:
        self.config = config
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN", None)
        self.imds_creds_expiration = None
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.server_id = server_id
        self.role = role
        self.mount_point = mount_point
        self.token = ""
        self.expires = None

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        if not self.access_key or not self.secret_key:
            self.access_key, self.secret_key = get_aws_credentials_from_env()
            if not self.access_key or not self.secret_key:
                self.access_key, self.secret_key = await cbasyncio.to_thread.run_sync(get_aws_credentials_from_file)

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            try:
                await response.aread()
                request = flow.send(response)
            except StopIteration:
                break

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if not self.access_key or not self.secret_key:
            self.access_key, self.secret_key = get_aws_credentials_from_env()
            if not self.access_key or not self.secret_key:
                self.access_key, self.secret_key = get_aws_credentials_from_file()

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            try:
                response.read()
                request = flow.send(response)
            except StopIteration:
                break

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self.needs_imds_refresh():
            logger.info("Fetching AWS credentials from IMDS")

            flow = self.imds_flow()
            req = next(flow)

            while True:
                response = yield req
                try:
                    req = flow.send(response)
                except StopIteration:
                    break

        if self.needs_refresh() and self.access_key and self.secret_key:
            logger.info("Refreshing AWS credentials")
            self.update_tokens((yield self.build_refresh_request()))

        request.headers["X-Vault-Token"] = self.token
        response = yield request

        if response.status_code == 401:
            logger.info("Refreshing AWS credentials")
            self.update_tokens((yield self.build_refresh_request()))
            request.headers["X-Vault-Token"] = self.token
            yield request

    def imds_flow(self) -> Generator[httpx.Request, httpx.Response, None]:
        response = yield (req := self.fetch_metadata_token_request())

        token: Optional[str] = None
        if response.status_code == 200:
            token = response.text
        elif response.status_code == 400:
            raise httpx.HTTPStatusError("bad idms request", request=req, response=response)
        elif response.status_code in (404, 403, 405):
            logger.info("Got %d from IMDS, assuming no token", response.status_code)
        elif response.status_code != 200:
            raise httpx.HTTPStatusError("unknown idms error", request=req, response=response)

        response = yield (req := self.get_iam_role_request(token))
        if not response.is_success:
            raise httpx.HTTPStatusError("error getting iam role", request=req, response=response)

        role_name = response.text
        response = yield self.get_iam_creds_request(role_name, token)
        if not response.is_success:
            raise httpx.HTTPStatusError("error getting iam creds", request=req, response=response)

        data: Dict[str, Any] = response.json()
        self.access_key = data["AccessKeyId"]
        self.secret_key = data["SecretAccessKey"]
        self.session_token = data.get("Token")
        if expiration := data.get("Expiration"):
            self.imds_creds_expiration = datetime.strptime(expiration, "%Y-%m-%dT%H:%M:%SZ")

    def needs_refresh(self) -> bool:
        return not self.token or (self.expires is not None and self.expires < datetime.utcnow())

    def needs_imds_refresh(self) -> bool:
        if not self.access_key or not self.secret_key:
            return True
        return self.imds_creds_expiration is not None and self.imds_creds_expiration < datetime.utcnow()

    def build_refresh_request(self) -> httpx.Request:
        base_url = self.config.address.rstrip("/") + "/v1"
        api_path = f"{base_url}/auth/{self.mount_point}/login"
        auth = SigV4Auth(
            "sts",
            access_key=self.access_key or "",
            secret_key=self.secret_key or "",
            session_token=self.session_token,
            region=self.region,
        )
        req = auth.add_auth(generate_sigv4_auth_request(server_id=self.server_id))

        params = {
            "iam_http_request_method": req.method,
            "iam_request_url": b64encode(str(req.url).encode("utf-8")).decode("utf-8"),
            "iam_request_headers": b64encode(json.dumps(dict(req.headers)).encode("utf-8")).decode("utf-8"),
            "iam_request_body": b64encode(req.content).decode("utf-8"),
            "role": self.role,
        }
        return httpx.Request("POST", api_path, json=params)

    def update_tokens(self, response: httpx.Response) -> None:
        record = response.json()

        if "auth" not in record:
            raise ValueError("No auth data in response")

        auth = record["auth"]
        if not isinstance(auth, dict):
            raise ValueError(f"Invalid auth data in response: {auth!r}")

        auth = cast(Dict[str, Any], auth)

        self.token = auth["client_token"]
        if lease_duration := auth["lease_duration"]:
            self.expires = datetime.now() + timedelta(seconds=lease_duration)
        else:
            self.expires = None

    def fetch_metadata_token_request(self) -> httpx.Request:
        headers = {"x-aws-ec2-metadata-token-ttl-seconds": "21600"}
        return httpx.Request("PUT", f"{METADATA_BASE_URL}/latest/api/token", headers=headers)

    def get_iam_role_request(self, token: Optional[str] = None) -> httpx.Request:
        headers = {}
        if token is not None:
            headers["x-aws-ec2-metadata-token"] = token

        return httpx.Request("GET", f"{METADATA_BASE_URL}/latest/meta-data/iam/security-credentials/", headers=headers)

    def get_iam_creds_request(self, role_name: str, token: Optional[str]) -> httpx.Request:
        headers = {}
        if token is not None:
            headers["x-aws-ec2-metadata-token"] = token

        url = f"{METADATA_BASE_URL}/latest/meta-data/iam/security-credentials/{role_name}"
        return httpx.Request("GET", url, headers=headers)


class SigV4Auth(object):
    region: str
    session_token: Optional[str]
    secret_key: str
    access_key: str
    service: str

    def __init__(
        self,
        service: str,
        *,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.service = service
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN", None)
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    def add_auth(self, req: httpx.Request) -> httpx.Request:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        req.headers["X-Amz-Date"] = timestamp

        if self.session_token:
            req.headers["X-Amz-Security-Token"] = self.session_token

        params: Dict[str, Any] = dict(parse_qsl(req.url.query.decode("utf-8"), keep_blank_values=True))
        query = urlencode(sorted(params.items()))

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        canonical_headers = "".join("{0}:{1}\n".format(k.lower(), req.headers[k]) for k in sorted(req.headers))
        signed_headers = ";".join(k.lower() for k in sorted(req.headers))
        payload_hash = sha256(req.content).hexdigest()
        canonical_request = "\n".join(
            [req.method, req.url.path or "/", query, canonical_headers, signed_headers, payload_hash]
        )

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "/".join([timestamp[0:8], self.region, self.service, "aws4_request"])
        canonical_request_hash = sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join([algorithm, timestamp, credential_scope, canonical_request_hash])

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        key = "AWS4{0}".format(self.secret_key).encode("utf-8")
        key = hmac.new(key, timestamp[0:8].encode("utf-8"), sha256).digest()
        key = hmac.new(key, self.region.encode("utf-8"), sha256).digest()
        key = hmac.new(key, self.service.encode("utf-8"), sha256).digest()
        key = hmac.new(key, "aws4_request".encode("utf-8"), sha256).digest()
        signature = hmac.new(key, string_to_sign.encode("utf-8"), sha256).hexdigest()

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
        authorization = "{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}".format(
            algorithm,
            self.access_key,
            credential_scope,
            signed_headers,
            signature,
        )

        req.headers["X-Amz-Content-Sha256"] = payload_hash
        req.headers["Authorization"] = authorization
        return req


def generate_sigv4_auth_request(server_id: Optional[str] = None) -> httpx.Request:
    request = httpx.Request(
        method="POST",
        url="https://sts.amazonaws.com/",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Host": "sts.amazonaws.com",
        },
        content=b"Action=GetCallerIdentity&Version=2011-06-15",
    )

    if server_id:
        request.headers["X-Vault-AWS-IAM-Server-ID"] = server_id

    return request


def get_aws_credentials_from_env() -> Tuple[Optional[str], Optional[str]]:
    access_key = os.getenv("AWS_ACCESS_KEY_ID", None)
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", None)
    return (access_key, secret_key)


def get_aws_credentials_from_file() -> Tuple[Optional[str], Optional[str]]:
    credentials_path = Path(os.getenv("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")).expanduser()
    if not credentials_path.exists() or not credentials_path.is_file():
        return (None, None)

    import configparser

    with credentials_path.open() as f_in:
        config = configparser.ConfigParser()
        config.read_file(f_in, source=credentials_path.as_posix())
        return (
            config.get("default", "aws_access_key_id", fallback=None),
            config.get("default", "aws_secret_access_key", fallback=None),
        )
