# Core Caddy alert metadata repair

The existing core Prometheus Caddy rule file supplies only severity.
Alertmanager therefore receives CaddyMTLSProbeFailure with the inherited
environment codestra_production_like and no service or owner. It misses the
production critical route.

The compatibility rule file retains every alert name, expression, threshold and
duration from the observed core deployment. It adds explicit production, caddy,
codestra business and operator ownership plus actionable annotations.
It belongs to Prometheus alert evaluation; it changes no Caddy runtime config.

Validate this file and rules.test.yml using the exact running promtool. Before
installation, compare every existing expression and duration to the candidate,
back up the original file and record its SHA-256. Preserve ownership and mode.
Replace only the existing Caddy rules file, reload Prometheus, verify reload
success and unchanged scrape health, and read back the same firing alert with
complete labels and the intended central receivers. Alert fingerprints change
when labels change; retain the old resolved transition and new firing evidence.
Rollback restores the previous rules and reloads Prometheus.

Investigate mTLS failures using the approved probe target, certificate chain,
validity, SAN, required client identity and revocation bundle. Do not disable
certificate verification or remove the authentication requirement to clear the
alert. Other Caddy alerts require the corresponding service, drift, backup,
canary, restart, certificate-renewal or reload evidence.
