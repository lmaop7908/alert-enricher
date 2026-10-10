"""HTTP helper with timeouts and polite retry/backoff for rate-limited APIs."""

from __future__ import annotations

import time

import requests

DEFAULT_TIMEOUT = 15
MAX_RETRIES = 3


class ProviderError(Exception):
    """Raised when a provider request fails in a way the caller should report."""


def request_with_retry(
    session: requests.Session,
    method: str,
    url: str,
    *,
    max_retries: int = MAX_RETRIES,
    sleep=time.sleep,
    **kwargs,
) -> requests.Response:
    """Send a request, retrying on 429 and 5xx with exponential backoff."""
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    last_error = "unknown error"

    for attempt in range(max_retries + 1):
        try:
            response = session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            last_error = f"network error: {exc.__class__.__name__}"
            if attempt == max_retries:
                break
            sleep(2**attempt)
            continue

        if response.status_code == 429 or response.status_code >= 500:
            last_error = f"HTTP {response.status_code}"
            if attempt == max_retries:
                break
            retry_after = response.headers.get("Retry-After", "")
            delay = int(retry_after) if retry_after.isdigit() else 2**attempt
            sleep(min(delay, 30))
            continue

        return response

    raise ProviderError(f"{last_error} after {max_retries + 1} attempts")
