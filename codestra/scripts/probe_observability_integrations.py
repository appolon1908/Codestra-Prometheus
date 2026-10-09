#!/usr/bin/env python3
"""Probe governed observability APIs using read-only requests and mTLS."""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

CODESTRA = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = CODESTRA / "catalog" / "observability-api-contract.v1.yml"
READ_ONLY_METHODS = {"GET", "HEAD"}
PROBE_FIELDS = ("health", "readiness", "metrics", "status")


class RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep an mTLS probe bound to the exact governed HTTPS endpoint."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def load_contract(path: Path) -> dict[str, Any]:
    contract = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(contract, dict) or contract.get("version") != 1:
        raise ValueError("unsupported observability contract")
    security = contract.get("security", {})
    if security.get("transport") != "mtls":
        raise ValueError("contract must require mTLS")
    if contract.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        raise ValueError("runtime probe requires fail-closed source status")
    return contract


def endpoint_url(service: dict[str, Any], endpoint: dict[str, Any]) -> str | None:
    method = str(endpoint.get("method", "GET")).upper()
    if method not in READ_ONLY_METHODS:
        return None
    direct = endpoint.get("endpoint")
    if direct:
        url = str(direct)
    else:
        base = service.get("base_url")
        path = endpoint.get("path")
        if not base or path is None:
            return None
        url = urllib.parse.urljoin(str(base).rstrip("/") + "/", str(path).lstrip("/"))
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("governed probe endpoint must use HTTPS")
    return url


def collect_probes(contract: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    probes: list[tuple[str, str, str, str]] = []
    services = contract.get("services", {})
    for service_name, service in sorted(services.items()):
        if not isinstance(service, dict):
            raise ValueError(f"invalid service definition: {service_name}")
        for field in PROBE_FIELDS:
            endpoint = service.get(field)
            if not isinstance(endpoint, dict):
                continue
            url = endpoint_url(service, endpoint)
            if url:
                probes.append(
                    (service_name, field, str(endpoint.get("method", "GET")).upper(), url)
                )
    if not probes:
        raise ValueError("contract contains no read-only probes")
    return probes


def ssl_context(ca_file: Path, cert_file: Path, key_file: Path) -> ssl.SSLContext:
    for path in (ca_file, cert_file, key_file):
        if not path.is_file():
            raise ValueError(f"required TLS file is unavailable: {path}")
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def probe(
    contract: dict[str, Any],
    context: ssl.SSLContext,
    timeout: float,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    opener = urllib.request.build_opener(
        RejectRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    for service, check, method, url in collect_probes(contract):
        started = time.monotonic()
        status: int | None = None
        outcome = "FAIL"
        error_class: str | None = None
        try:
            request = urllib.request.Request(
                url,
                method=method,
                headers={"Accept": "application/json, text/plain;q=0.9"},
            )
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                response.read(1024)
                final_url = response.geturl()
            if final_url != url:
                error_class = "redirect"
            else:
                outcome = "PASS" if 200 <= status < 300 else "FAIL"
        except urllib.error.HTTPError as exc:
            status = exc.code
            error_class = "redirect" if 300 <= exc.code < 400 else "http_error"
        except urllib.error.URLError as exc:
            reason = exc.reason
            error_class = (
                "tls_error" if isinstance(reason, ssl.SSLError)
                else "timeout" if isinstance(reason, (TimeoutError, socket.timeout))
                else "connection_error"
            )
        except (TimeoutError, socket.timeout):
            error_class = "timeout"
        results.append(
            {
                "service": service,
                "check": check,
                "method": method,
                "outcome": outcome,
                "status_code": status,
                "error_class": error_class,
                "latency_ms": round((time.monotonic() - started) * 1000),
            }
        )
    passed = sum(item["outcome"] == "PASS" for item in results)
    return {
        "schema_version": "1.0",
        "mode": "read_only_mtls",
        "business_writes_performed": False,
        "credentials_recorded": False,
        "summary": {"passed": passed, "failed": len(results) - passed, "total": len(results)},
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--cert-file", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0 < args.timeout <= 30:
        raise SystemExit("timeout must be greater than 0 and no more than 30 seconds")
    evidence = probe(
        load_contract(args.contract),
        ssl_context(args.ca_file, args.cert_file, args.key_file),
        args.timeout,
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        args.output.chmod(0o600)
    else:
        print(rendered, end="")
    return 0 if evidence["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
