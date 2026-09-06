# Upstream source and runtime authority

## Production authority

The production runtime is the immutable Prometheus `v3.5.0` image locked in
`codestra/release/runtime-image.lock.json`:

```text
docker.io/prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996
release commit: 8be3a9560fbdd18a94dedec4b747c35178177202
```

Every repository PromQL, configuration, and rule-evaluation gate runs the
`/bin/promtool` contained in that exact image. Vendored Go source is not used
to approve runtime configuration.

## Vendored source reference

`upstream/` is retained only as an exact, reviewable source reference:

```text
commit: e06b2dc5a6149e20ca82fe936fb044a6dfe45958
tree:   9f3cc4b95e5d0ea24656c2c237a13aa26aa62f29
role:   NON_RUNTIME_REFERENCE
```

`CODESTRA_UPSTREAM.json`, `CODESTRA_UPSTREAM_LOCK.json`, the Git tree at
`HEAD:upstream`, and the official Prometheus commit tree must all match. The
read-only source-authority workflow verifies official ancestry and tree
identity. It has no permission or command capable of pushing a branch,
opening a pull request, deploying, or activating a target.

## Updating the source reference

1. Select an exact 40-character upstream commit reachable from the trusted
   Prometheus reference.
2. Record its exact Git tree and commit timestamp in both source documents.
3. Materialize that exact tree under `upstream/` on a feature branch.
4. Run the source-authority, repository-readiness, corporate-runtime, and
   configuration gates.
5. Merge only through protected review. Never write directly to `main`,
   `staging`, or `production`.

Changing the non-runtime source reference does not change the runtime image.
A runtime version change requires a separately reviewed image lock, manifest,
configuration validation, rollback evidence, and production activation
decision.
