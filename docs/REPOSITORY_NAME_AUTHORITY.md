# Repository-name and private exporter authority

## Stable identities

Repository names are operational aliases. The stable identity used by this repository is the GitHub repository ID recorded in
`codestra/catalog/repository-name-aliases.v1.json`.

Current verified authorities:

- PostgreSQL Exporter: repository ID `1350839865`, `appolon1908-hue/Codestra-Postgres-Exporter`;
- Restaurant frontend: repository ID `1221155447`, current repository `appolon1908-hue/Frontend-Resturant-`;
- Rename documentation: repository ID `1350724356`, `appolon1908-hue/documentaions`.

The misspelled restaurant repository name remains authoritative until GitHub cutover and every dependent reference, workflow, deploy key, image name, server checkout, and rollback record has been migrated. This Prometheus repository must not silently switch to `appolon1908-hue/restaurant-frontend` before that cutover.

## PostgreSQL Exporter boundary

PostgreSQL Exporter is owned by its separate component repository. Codestra Prometheus records only its private scrape identity:

```text
postgres-exporter:9187
```

The following remain prohibited:

- a public PostgreSQL Exporter hostname or route;
- host-port publication from this repository;
- a `postgres-exporter` runtime service in `codestra/compose.yaml`;
- DNS, hosts-file, link, network-mode, or Compose-extends overrides that shadow the private identity;
- production target activation without separately reviewed runtime and access evidence.

The production target remains `activation=pending`. The retired hostname `pgex.codestra.media` is retained only as a forbidden value in the alias authority and tests; it must not appear in operational configuration.

## Controlled rename

A rename may proceed only when all of the following are true:

1. The GitHub repository itself has been renamed or an approved replacement exists.
2. The stable repository ID is unchanged or an explicit migration record binds old and new IDs.
3. GitHub Actions, branch rules, deploy keys, image references, manifests, server checkouts, documentation, and observability catalogs are migrated in one reviewed plan.
4. A rollback path and compatibility window are recorded in the documentation authority.
5. The alias manifest status is changed through a protected pull request with exact-head tests.

## Validation

Run:

```bash
python scripts/validate_repository_alias_authority.py
python tests/test_repository_alias_authority.py
```

The repository-readiness gate invokes the same authority validator, so a direct drift cannot pass the canonical promotion workflow.
