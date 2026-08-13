"""Bounded standard-library HTTPS transport for connector adapters."""

from __future__ import annotations

import asyncio
import ssl
import urllib.error
import urllib.request

from aegis_agent_platform.evidence.ports import (
    ConnectorError,
    ConnectorErrorClass,
    HttpRequest,
    HttpResponse,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> urllib.request.Request | None:
        del request, file_pointer, code, message, headers, new_url
        return None


class UrlLibHttpTransport:
    """HTTPS transport with certificate validation and hard response caps."""

    def __init__(self, *, proxy_url: str | None = None) -> None:
        self._proxy_url = proxy_url

    async def send(self, request: HttpRequest) -> HttpResponse:
        return await asyncio.to_thread(self._send, request)

    def _send(self, request: HttpRequest) -> HttpResponse:
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        ]
        if self._proxy_url is not None:
            handlers.append(urllib.request.ProxyHandler({"https": self._proxy_url}))
        opener = urllib.request.build_opener(*handlers)
        outgoing = urllib.request.Request(  # noqa: S310 - URL is HTTPS-validated
            request.url,
            data=request.body,
            headers=dict(request.headers),
            method=request.method,
        )
        try:
            with opener.open(outgoing, timeout=request.timeout_seconds) as response:
                body = response.read(request.max_response_bytes + 1)
                if len(body) > request.max_response_bytes:
                    raise ConnectorError(
                        ConnectorErrorClass.RESPONSE_TOO_LARGE,
                        "response_size_cap_exceeded",
                        retryable=False,
                        partial=True,
                    )
                return HttpResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=body,
                )
        except ConnectorError:
            raise
        except TimeoutError as error:
            raise ConnectorError(
                ConnectorErrorClass.TIMEOUT,
                "connector_timeout",
                retryable=True,
            ) from error
        except urllib.error.HTTPError as error:
            body = error.read(request.max_response_bytes + 1)
            return HttpResponse(
                status=error.code,
                headers=dict(error.headers.items()),
                body=body[: request.max_response_bytes],
            )
        except (urllib.error.URLError, OSError) as error:
            raise ConnectorError(
                ConnectorErrorClass.UNAVAILABLE,
                "connector_transport_unavailable",
                retryable=True,
            ) from error


__all__ = ["UrlLibHttpTransport"]
