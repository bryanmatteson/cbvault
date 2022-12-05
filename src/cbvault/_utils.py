from typing import Any, Mapping, MutableMapping

import cbvault.errors as errors


def raise_for_error(method: str, url: str, status_code: int, message: str):
    """Helper method to raise exceptions based on the status code of a response received back from Vault."""

    if status_code == 400:
        raise errors.InvalidRequest(message, method=method, url=url)
    elif status_code == 401:
        raise errors.Unauthorized(message, method=method, url=url)
    elif status_code == 403:
        raise errors.Forbidden(message, method=method, url=url)
    elif status_code == 404:
        raise errors.InvalidPath(message, method=method, url=url)
    elif status_code == 429:
        raise errors.RateLimitExceeded(message, method=method, url=url)
    elif status_code == 500:
        raise errors.InternalServerError(message, method=method, url=url)
    elif status_code == 501:
        raise errors.VaultNotInitialized(message, method=method, url=url)
    elif status_code == 502:
        raise errors.BadGateway(message, method=method, url=url)
    elif status_code == 503:
        raise errors.VaultDown(message, method=method, url=url)
    else:
        raise errors.UnexpectedError(message, method=method, url=url)


def remove_nones(params: Mapping[str, Any]) -> MutableMapping[str, Any]:
    """Removes None values from optional arguments in a parameter dictionary."""

    return {key: value for key, value in params.items() if value is not None}


def normalize_path(url: str) -> str:
    while "//" in url:
        url = url.replace("//", "/")
    return url


def format_url(format_str: str, *args: Any, **kwargs: Any) -> str:
    """Creates a URL using the specified format after escaping the provided arguments."""

    from urllib.parse import quote

    escaped_args = [quote(value) for value in args]
    escaped_kwargs = {key: quote(value) for key, value in kwargs.items()}
    return format_str.format(*escaped_args, **escaped_kwargs)


def url_join(*args: str) -> str:
    return "/".join(map(lambda x: x.strip("/"), args))
