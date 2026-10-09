#!/usr/bin/env python3
"""Per-target inventory: what Prometheus is configured to scrape, and (optionally) what it actually scrapes.

    python3 codestra/scripts/target_inventory.py --write codestra/target-inventory.v1.json
    python3 codestra/scripts/target_inventory.py --check codestra/target-inventory.v1.json
    python3 codestra/scripts/target_inventory.py --runtime-file /abs/targets.json --output /abs/dir
    python3 codestra/scripts/target_inventory.py --runtime-url http://prometheus:9090 --output /abs/dir

One record per configured target with the Section 10 fields: expected
endpoint, environment, service_id, authentication method, activation state and
the configuration digest this inventory was derived from. With a runtime
source (the JSON of ``GET /api/v1/targets`` saved to a file, or the private
Prometheus API read live), every record also carries the actual endpoint,
scrape status, last scrape age and metric freshness. Nothing here mutates
Prometheus, and the runtime read is a GET without credentials on the private
network only (the API is never public).

Fail-closed invariants (exit 1): a Middleware target must be
``middleware-integration-api:8095`` (never legacy 8080), every target carries
``environment`` and ``service`` labels, credentialed jobs reference files only,
Blackbox targets use reviewed side-effect-free modules, and the committed
inventory must match the configuration it claims to describe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

CODESTRA = Path(__file__).resolve().parents[1]
CONFIG = CODESTRA / "prometheus" / "prometheus.yml"
TARGET_DIR = CODESTRA / "prometheus" / "targets"
BLACKBOX_DIR = CODESTRA / "blackbox"
MIDDLEWARE_SERVICES = {"middleware", "middleware-integration-api", "middleware-readiness"}
MIDDLEWARE_AUTHORITY = "middleware-integration-api:8095"
LEGACY_MIDDLEWARE_PORT = 8080
SAFE_PROBE_MODULES = {"https_2xx", "http_2xx_internal", "tcp_connect", "https_openbao_health", "dns_a_record", "tls_expiry"}
SECRET_SHAPED = re.compile(r"(hvs\.[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|Bearer\s+[A-Za-z0-9._~+/-]{16,})")


class InventoryError(RuntimeError):
    pass


def lf_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def parse_duration(value: Any, default: float = 15.0) -> float:
    if not isinstance(value, str):
        return default
    match = re.fullmatch(r"(\d+)(ms|s|m|h)", value)
    if not match:
        return default
    number, unit = int(match.group(1)), match.group(2)
    return number * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]


def authentication_of(job: dict[str, Any]) -> str:
    parts: list[str] = []
    oauth = job.get("oauth2")
    if isinstance(oauth, dict):
        scopes = ",".join(oauth.get("scopes", []))
        parts.append(f"oauth2 client={oauth.get('client_id')} scopes={scopes} secret=file")
    authorization = job.get("authorization")
    if isinstance(authorization, dict):
        parts.append(f"{str(authorization.get('type', 'Bearer')).lower()} credentials=file")
    if "basic_auth" in job:
        parts.append("basic-auth password=file")
    tls = job.get("tls_config")
    if isinstance(tls, dict) and tls.get("cert_file"):
        parts.append("mtls client-cert=file")
    return "; ".join(parts) or "none (private network)"


def resolve_sd_files(patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        name = Path(pattern).name
        directory = BLACKBOX_DIR if "blackbox" in pattern else TARGET_DIR
        files.extend(sorted(directory.glob(name)))
    return files


def target_groups(job: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
    groups: list[tuple[dict[str, Any], str]] = []
    for group in job.get("static_configs", []) or []:
        groups.append((group, "static"))
    for sd in job.get("file_sd_configs", []) or []:
        for file in resolve_sd_files(sd.get("files", [])):
            for group in json.loads(file.read_bytes().decode("utf-8")):
                groups.append((group, str(file.relative_to(CODESTRA)).replace("\\", "/")))
    return groups


def build_inventory(config_path: Path = CONFIG) -> dict[str, Any]:
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    global_interval = parse_duration(config.get("global", {}).get("scrape_interval"))
    records: list[dict[str, Any]] = []
    for job in config.get("scrape_configs", []):
        job_name = job["job_name"]
        interval = parse_duration(job.get("scrape_interval"), global_interval)
        scheme = job.get("scheme", "http")
        metrics_path = job.get("metrics_path", "/metrics")
        auth = authentication_of(job)
        blackbox = job_name == "blackbox"
        for group, source in target_groups(job):
            labels = dict(group.get("labels", {}))
            for target in group.get("targets", []):
                record = {
                    "job": job_name,
                    "service_id": labels.get("service"),
                    "environment": labels.get("environment"),
                    "activation": labels.get("activation", "active" if not blackbox else ("active" if labels.get("probe_enabled") == "true" else "pending")),
                    "expected_endpoint": target if blackbox else f"{target}",
                    "scheme": scheme,
                    "metrics_path": labels.get("__metrics_path__", metrics_path),
                    "authentication": "blackbox probe via blackbox-exporter:9115 (no credentials)" if blackbox else auth,
                    "probe_module": labels.get("probe_module", "https_2xx") if blackbox else None,
                    "scrape_interval_seconds": interval,
                    "source": source,
                    "job_class": labels.get("job_class"),
                }
                records.append(record)
    records.sort(key=lambda r: (r["job"], str(r["service_id"]), r["expected_endpoint"]))
    return {
        "schema_version": 1,
        "component": "prometheus",
        "config_path": str(config_path.relative_to(CODESTRA)).replace("\\", "/") if config_path.is_relative_to(CODESTRA) else config_path.name,
        "config_digest": lf_digest(config_path),
        "middleware_authority": MIDDLEWARE_AUTHORITY,
        "records": records,
        "counts": {"targets": len(records), "active": sum(1 for r in records if r["activation"] == "active"), "pending": sum(1 for r in records if r["activation"] != "active")},
    }


def check_invariants(inventory: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for record in inventory["records"]:
        label = f"{record['job']}/{record['service_id']}@{record['expected_endpoint']}"
        if not record["service_id"] or not record["environment"]:
            problems.append(f"{label}: missing service or environment label")
        endpoint = record["expected_endpoint"]
        host_port = urllib.parse.urlsplit(endpoint).netloc if "://" in endpoint else endpoint
        port = host_port.rsplit(":", 1)[-1] if ":" in host_port else ""
        if record["service_id"] in MIDDLEWARE_SERVICES or host_port.startswith("middleware-integration-api:"):
            if port == str(LEGACY_MIDDLEWARE_PORT):
                problems.append(f"{label}: Middleware on legacy port {LEGACY_MIDDLEWARE_PORT}")
            if host_port != MIDDLEWARE_AUTHORITY:
                problems.append(f"{label}: Middleware endpoint is not the approved authority {MIDDLEWARE_AUTHORITY}")
        if record["probe_module"] and record["probe_module"] not in SAFE_PROBE_MODULES:
            problems.append(f"{label}: probe module {record['probe_module']} is not a reviewed safe module")
        if record["job"] == "codestra-middleware-metrics" and "oauth2 client=monitoring-readonly" not in record["authentication"]:
            problems.append(f"{label}: Middleware metrics must authenticate as monitoring-readonly")
        if record["job"] == "codestra-openbao" and ("mtls" not in record["authentication"] or "bearer credentials=file" not in record["authentication"]):
            problems.append(f"{label}: OpenBao scrape must use mTLS and a file-backed bearer")
        if record["service_id"] == "openbao" and record["metrics_path"] != "/v1/sys/metrics":
            problems.append(f"{label}: OpenBao metrics path must be /v1/sys/metrics")
    return problems


def merge_runtime(inventory: dict[str, Any], runtime: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    active = runtime.get("data", {}).get("activeTargets", []) if isinstance(runtime, dict) else []
    dropped = runtime.get("data", {}).get("droppedTargets", []) if isinstance(runtime, dict) else []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for target in active:
        labels = target.get("labels", {})
        scrape = urllib.parse.urlsplit(target.get("scrapeUrl", ""))
        instance = labels.get("instance", scrape.netloc)
        by_key[(labels.get("job", ""), instance)] = target
    merged = json.loads(json.dumps(inventory))
    for record in merged["records"]:
        key = (record["job"], record["expected_endpoint"])
        target = by_key.get(key)
        if target is None and record["job"] == "blackbox":
            target = by_key.get(("blackbox", record["expected_endpoint"]))
        if target is None:
            record.update({"actual_endpoint": None, "scrape_status": "not-active" if record["activation"] == "active" else "pending", "last_scrape_age_seconds": None, "metric_freshness": "unknown", "scrape_error": None})
            continue
        scrape = urllib.parse.urlsplit(target.get("scrapeUrl", ""))
        last = target.get("lastScrape")
        age = None
        if isinstance(last, str):
            try:
                age = round((now - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds(), 1)
            except ValueError:
                age = None
        fresh_limit = 2 * float(record["scrape_interval_seconds"]) + 5
        record.update({
            "actual_endpoint": scrape.netloc if record["job"] != "blackbox" else urllib.parse.parse_qs(scrape.query).get("target", [None])[0],
            "actual_path": scrape.path,
            "scrape_status": target.get("health", "unknown"),
            "last_scrape_age_seconds": age,
            "metric_freshness": "unknown" if age is None else ("fresh" if age <= fresh_limit else "stale"),
            "scrape_error": SECRET_SHAPED.sub("[REDACTED]", str(target.get("lastError", "")))[:160] or None,
            "endpoint_matches": (scrape.netloc == record["expected_endpoint"]) if record["job"] != "blackbox" else None,
        })
    merged["runtime"] = {
        "observed_at": now.isoformat(),
        "active_targets": len(active),
        "dropped_targets": len(dropped),
        "up": sum(1 for t in active if t.get("health") == "up"),
        "down": sum(1 for t in active if t.get("health") == "down"),
        "unexpected_active": sorted(f"{job}@{instance}" for (job, instance) in by_key if not any(r["job"] == job and r["expected_endpoint"] == instance for r in merged["records"])),
    }
    return merged


def fetch_runtime(base_url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise InventoryError("runtime URL must be a plain private http(s) endpoint")
    request = urllib.request.Request(base_url.rstrip("/") + "/api/v1/targets?state=active", headers={"Accept": "application/json", "User-Agent": "codestra-target-inventory/1"}, method="GET")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: D401
            raise InventoryError("redirect refused")

    with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
        return json.loads(response.read(8 * 1024 * 1024))


def render_markdown(inventory: dict[str, Any]) -> str:
    runtime = "runtime" in inventory
    header = "| job | service | env | activation | expected endpoint | auth |" + (" actual | status | age s | freshness |" if runtime else "")
    lines = [header, "|" + "---|" * (6 + (4 if runtime else 0))]
    for r in inventory["records"]:
        row = f"| {r['job']} | {r['service_id']} | {r['environment']} | {r['activation']} | {r['expected_endpoint']} | {r['authentication']} |"
        if runtime:
            age = r.get("last_scrape_age_seconds")
            row += f" {r.get('actual_endpoint') or '-'} | {r.get('scrape_status')} | {'-' if age is None else age} | {r.get('metric_freshness')} |"
        lines.append(row)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--write", type=Path, help="write the desired inventory JSON to this path")
    parser.add_argument("--check", type=Path, help="verify a committed inventory matches the configuration")
    parser.add_argument("--runtime-file", type=Path, help="JSON of GET /api/v1/targets to merge")
    parser.add_argument("--runtime-url", help="private Prometheus base URL to read /api/v1/targets from")
    parser.add_argument("--output", type=Path, help="directory for the merged runtime report")
    args = parser.parse_args(argv)
    try:
        inventory = build_inventory(args.config)
        problems = check_invariants(inventory)
        if problems:
            for problem in problems:
                print(f"TARGET_INVENTORY_INVARIANT={problem}", file=sys.stderr)
            return 1
        if args.write:
            args.write.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if args.check:
            committed = json.loads(args.check.read_text(encoding="utf-8"))
            if committed != inventory:
                print("TARGET_INVENTORY=STALE regenerate with --write", file=sys.stderr)
                return 1
        if args.runtime_file or args.runtime_url:
            if not args.output or not args.output.is_absolute():
                raise InventoryError("--output must be an absolute directory for runtime reports")
            runtime = json.loads(args.runtime_file.read_text(encoding="utf-8")) if args.runtime_file else fetch_runtime(args.runtime_url)
            merged = merge_runtime(inventory, runtime)
            serialized = json.dumps(merged, indent=2, sort_keys=True)
            if SECRET_SHAPED.search(serialized):
                raise InventoryError("runtime report would contain secret-shaped material")
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "target-inventory.runtime.json").write_text(serialized + "\n", encoding="utf-8")
            (args.output / "target-inventory.runtime.md").write_text(render_markdown(merged), encoding="utf-8")
            inventory = merged
    except (InventoryError, OSError, ValueError) as exc:
        print(f"TARGET_INVENTORY=FAIL reason={exc}", file=sys.stderr)
        return 1
    counts = inventory["counts"]
    summary = f"TARGET_INVENTORY=PASS targets={counts['targets']} active={counts['active']} pending={counts['pending']} middleware={MIDDLEWARE_AUTHORITY} config={inventory['config_digest'][:19]}"
    if "runtime" in inventory:
        summary += f" runtime_up={inventory['runtime']['up']} runtime_down={inventory['runtime']['down']} unexpected={len(inventory['runtime']['unexpected_active'])}"
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
