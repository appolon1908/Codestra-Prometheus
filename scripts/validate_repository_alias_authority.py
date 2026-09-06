#!/usr/bin/env python3
"""Validate repository aliases and private PostgreSQL Exporter authority."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import yaml
from yaml.resolver import BaseResolver

ROOT = Path(__file__).resolve().parents[1]
ALIASES_PATH = ROOT / "codestra/catalog/repository-name-aliases.v1.json"
SERVICES_PATH = ROOT / "codestra/catalog/services.yml"
TARGETS_PATH = ROOT / "codestra/prometheus/targets/production.json"
COMPOSE_PATH = ROOT / "codestra/compose.yaml"

DOCUMENTATION_REPOSITORY_ID = 1350724356
DOCUMENTATION_REPOSITORY = "appolon1908-hue/documentaions"
DOCUMENTATION_PATH = "repository-name-migration.v1.json"
POSTGRES_REPOSITORY_ID = 1350839865
POSTGRES_REPOSITORY = "appolon1908-hue/Codestra-Postgres-Exporter"
POSTGRES_PRIVATE_IDENTITY = "postgres-exporter:9187"
FORBIDDEN_POSTGRES_HOSTNAME = "pgex.codestra.media"
RESTAURANT_REPOSITORY_ID = 1221155447
RESTAURANT_CURRENT_REPOSITORY = "appolon1908-hue/Frontend-Resturant-"
RESTAURANT_TARGET_REPOSITORY = "appolon1908-hue/restaurant-frontend"
OBSERVABILITY_NETWORK = "${CODESTRA_OBSERVABILITY_NETWORK:-codestra-observability}"
OPERATIONAL_PATHS = (
    "codestra/catalog/services.yml",
    "codestra/compose.yaml",
    "codestra/prometheus/prometheus.yml",
    "codestra/prometheus/prometheus-staging.yml",
    "codestra/prometheus/targets/production.json",
    "codestra/prometheus/targets/staging.json",
    "codestra/blackbox/targets-production.json",
    "codestra/enterprise-profile.v1.json",
)


class AuthorityError(ValueError):
    """Raised when repository-name or exporter authority drifts."""


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that resolves aliases and rejects duplicate keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"unhashable mapping key: {key!r}",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate mapping key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_regular(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise AuthorityError(f"required regular file missing: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def load_json_text(text: str, source: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, TypeError, AuthorityError) as error:
        raise AuthorityError(f"invalid JSON in {source}: {error}") from error


def load_yaml_text(text: str, source: str) -> object:
    try:
        return yaml.load(text, Loader=UniqueKeyLoader)
    except (yaml.YAMLError, TypeError, ValueError) as error:
        raise AuthorityError(f"invalid YAML in {source}: {error}") from error


def require_mapping(value: object, source: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise AuthorityError(f"{source} must be a string-keyed mapping")
    return value


def require_list(value: object, source: str) -> list[Any]:
    if not isinstance(value, list):
        raise AuthorityError(f"{source} must be a list")
    return value


def service_records(catalog: Mapping[str, Any], section: str, service: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in require_list(catalog.get(section), f"services catalog {section}"):
        if not isinstance(value, dict):
            raise AuthorityError(f"services catalog {section} contains a non-object record")
        if value.get("service") == service:
            records.append(value)
    return records


def load_operational_sources() -> dict[str, str]:
    return {relative: read_regular(ROOT / relative) for relative in OPERATIONAL_PATHS}


def validate_documents(
    aliases: Mapping[str, Any],
    catalog: Mapping[str, Any],
    targets: object,
    compose: Mapping[str, Any],
    operational_sources: Mapping[str, str],
) -> None:
    if aliases.get("schema_version") != "1.1":
        raise AuthorityError("repository alias schema_version must be 1.1")
    if aliases.get("status") != "PREPARED_NOT_RENAMED":
        raise AuthorityError("repository aliases must remain PREPARED_NOT_RENAMED")
    if aliases.get("identity_key") != "repository_id":
        raise AuthorityError("repository_id must remain the stable identity key")

    expected_documentation = {
        "repository_id": DOCUMENTATION_REPOSITORY_ID,
        "repository": DOCUMENTATION_REPOSITORY,
        "path": DOCUMENTATION_PATH,
    }
    if aliases.get("documentation_authority") != expected_documentation:
        raise AuthorityError("documentation repository authority drifted")

    expected_postgres = {
        "repository_id": POSTGRES_REPOSITORY_ID,
        "repository": POSTGRES_REPOSITORY,
        "public_hostname": None,
        "forbidden_public_hostname": FORBIDDEN_POSTGRES_HOSTNAME,
        "private_service_identity": POSTGRES_PRIVATE_IDENTITY,
        "exposure": "PRIVATE_INTERNAL_ONLY",
        "public_route_allowed": False,
        "host_public_port_allowed": False,
        "production_target_activation": "pending",
        "runtime_ownership": "EXTERNAL_COMPONENT_REPOSITORY",
        "compose_service_owned_here": False,
    }
    if aliases.get("postgres_exporter") != expected_postgres:
        raise AuthorityError("PostgreSQL Exporter authority drifted")

    mappings = require_list(aliases.get("mappings"), "repository mappings")
    expected_mapping = {
        "repository_id": RESTAURANT_REPOSITORY_ID,
        "current_repository": RESTAURANT_CURRENT_REPOSITORY,
        "target_repository_after_cutover": RESTAURANT_TARGET_REPOSITORY,
        "status": "PREPARED_NOT_RENAMED",
        "cutover_requirements": [
            "github_repository_rename_completed",
            "dependent_references_migrated",
            "rollback_recorded",
        ],
    }
    if mappings != [expected_mapping]:
        raise AuthorityError("restaurant repository rename authority drifted")

    authorities = require_mapping(catalog.get("authorities"), "services catalog authorities")
    if authorities.get("postgres_exporter") != POSTGRES_REPOSITORY:
        raise AuthorityError("services catalog PostgreSQL Exporter authority drifted")

    postgres_records = service_records(catalog, "infrastructure_services", "postgres-exporter")
    if len(postgres_records) != 1:
        raise AuthorityError("services catalog must contain one PostgreSQL Exporter record")
    postgres_record = postgres_records[0]
    if postgres_record.get("repo") != POSTGRES_REPOSITORY:
        raise AuthorityError("services catalog PostgreSQL Exporter repository drifted")
    if postgres_record.get("endpoint") != POSTGRES_PRIVATE_IDENTITY:
        raise AuthorityError("services catalog PostgreSQL Exporter endpoint is not private")

    restaurant_records = service_records(catalog, "application_services", "restaurant-backend")
    if len(restaurant_records) != 1:
        raise AuthorityError("services catalog must contain one restaurant-backend record")
    if restaurant_records[0].get("repo") != RESTAURANT_CURRENT_REPOSITORY:
        raise AuthorityError("restaurant repository changed before controlled cutover")

    catalog_text = operational_sources.get("codestra/catalog/services.yml", "")
    if RESTAURANT_TARGET_REPOSITORY in catalog_text:
        raise AuthorityError("target restaurant repository is active before cutover")

    target_groups = require_list(targets, "production targets")
    postgres_targets = [
        group
        for group in target_groups
        if isinstance(group, dict)
        and isinstance(group.get("labels"), dict)
        and group["labels"].get("service") == "postgres-exporter"
    ]
    if len(postgres_targets) != 1:
        raise AuthorityError("production targets must contain one PostgreSQL Exporter target")
    postgres_target = postgres_targets[0]
    labels = require_mapping(postgres_target.get("labels"), "PostgreSQL Exporter target labels")
    if postgres_target.get("targets") != [POSTGRES_PRIVATE_IDENTITY]:
        raise AuthorityError("production PostgreSQL Exporter target is not private")
    if labels.get("activation") != "pending":
        raise AuthorityError("production PostgreSQL Exporter target must remain pending")
    if labels.get("environment") != "production" or labels.get("tenant_scope") != "aggregate":
        raise AuthorityError("production PostgreSQL Exporter labels drifted")

    compose_services = require_mapping(compose.get("services"), "Compose services")
    if "postgres-exporter" in compose_services:
        raise AuthorityError("Prometheus repository may not own PostgreSQL Exporter runtime")
    if "prometheus" not in compose_services:
        raise AuthorityError("Prometheus Compose service is missing")

    networks = require_mapping(compose.get("networks"), "Compose networks")
    observability = require_mapping(networks.get("observability"), "observability network")
    if observability.get("external") is not True or observability.get("name") != OBSERVABILITY_NETWORK:
        raise AuthorityError("Prometheus must use the approved external observability network")

    prometheus = require_mapping(compose_services.get("prometheus"), "Prometheus Compose service")
    joined_networks = prometheus.get("networks")
    if isinstance(joined_networks, dict):
        joined = "observability" in joined_networks
    elif isinstance(joined_networks, list):
        joined = "observability" in joined_networks
    else:
        joined = False
    if not joined:
        raise AuthorityError("Prometheus must join the external observability network")
    for field in (
        "extra_hosts",
        "links",
        "external_links",
        "dns",
        "dns_opt",
        "dns_search",
        "network_mode",
        "extends",
    ):
        if field in prometheus:
            raise AuthorityError(f"Prometheus may not override private name resolution through {field}")

    for source, text in operational_sources.items():
        if FORBIDDEN_POSTGRES_HOSTNAME.lower() in text.lower():
            raise AuthorityError(f"retired public PostgreSQL Exporter hostname found in {source}")


def validate_repository() -> None:
    aliases = require_mapping(
        load_json_text(read_regular(ALIASES_PATH), str(ALIASES_PATH.relative_to(ROOT))),
        "repository alias authority",
    )
    catalog = require_mapping(
        load_yaml_text(read_regular(SERVICES_PATH), str(SERVICES_PATH.relative_to(ROOT))),
        "services catalog",
    )
    targets = load_json_text(read_regular(TARGETS_PATH), str(TARGETS_PATH.relative_to(ROOT)))
    compose = require_mapping(
        load_yaml_text(read_regular(COMPOSE_PATH), str(COMPOSE_PATH.relative_to(ROOT))),
        "Compose document",
    )
    validate_documents(
        aliases,
        catalog,
        targets,
        compose,
        load_operational_sources(),
    )


def main() -> None:
    try:
        validate_repository()
    except (AuthorityError, OSError) as error:
        raise SystemExit(f"REPOSITORY_ALIAS_AUTHORITY=FAIL ERROR={error}") from error
    print("REPOSITORY_ALIAS_AUTHORITY=PASS")
    print(f"POSTGRES_EXPORTER_REPOSITORY_ID={POSTGRES_REPOSITORY_ID}")
    print("POSTGRES_EXPORTER_EXPOSURE=PRIVATE_INTERNAL_ONLY")
    print("POSTGRES_EXPORTER_PRODUCTION_TARGET=pending")
    print(f"RESTAURANT_CURRENT_REPOSITORY_ID={RESTAURANT_REPOSITORY_ID}")
    print("RESTAURANT_RENAME_STATUS=PREPARED_NOT_RENAMED")


if __name__ == "__main__":
    main()
