#!/usr/bin/env python3
"""Prepare the existing core Prometheus client for the paired native mTLS cutover."""
from __future__ import annotations

import argparse
import copy
from pathlib import Path

import yaml

TARGET = "10.253.127.3:9093"
TLS = {
    "ca_file": "/run/secrets/core-alertmanager-ca",
    "cert_file": "/run/secrets/core-alertmanager-client-cert",
    "key_file": "/run/secrets/core-alertmanager-client-key",
    "server_name": "alertmanager.core.codestra.internal",
    "insecure_skip_verify": False,
    "min_version": "TLS12",
}


def secure(client: dict) -> None:
    if client.get("scheme", "http") not in ("http", "https"):
        raise ValueError("unexpected transport scheme")
    if client.get("tls_config") not in (None, TLS):
        raise ValueError("unexpected TLS configuration; inspect existing trust first")
    if any(k in client for k in ("authorization", "basic_auth", "oauth2")):
        raise ValueError("unexpected existing authentication")
    configs = client.get("static_configs", [])
    targets = [t for c in configs for t in c.get("targets", [])]
    if targets != [TARGET] or any(k.endswith("_sd_configs") for k in client):
        raise ValueError("expected the single existing core Alertmanager target")
    client["scheme"] = "https"
    client["tls_config"] = copy.deepcopy(TLS)


def configure(source: dict) -> dict:
    result = copy.deepcopy(source)
    managers = result.get("alerting", {}).get("alertmanagers", [])
    if len(managers) != 1:
        raise ValueError("expected exactly one existing Alertmanager configuration")
    secure(managers[0])
    if managers[0].get("api_version", "v2") != "v2":
        raise ValueError("the existing Alertmanager API must be v2")
    managers[0]["api_version"] = "v2"
    for job in result.get("scrape_configs", []):
        if any(TARGET in c.get("targets", []) for c in job.get("static_configs", [])):
            secure(job)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("output must be a separate candidate file")
    candidate = configure(yaml.safe_load(args.input.read_text()))
    with args.output.open("x", encoding="utf-8") as handle:
        yaml.safe_dump(candidate, handle, sort_keys=False)
    print("Candidate written. Apply only with the paired Alertmanager TLS cutover.")


if __name__ == "__main__":
    main()
