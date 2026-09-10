# Paired core Alertmanager TLS migration

The private provider listener prepared in Codestra-Alertmanager PR22 enables
native TLS on internal port 9093 too. The current core Prometheus sends alerts
to 10.253.127.3:9093 over HTTP. Applying only the server change would interrupt
that existing path.

scripts/configure_core_alertmanager_mtls.py prepares a separate candidate from
the actual running core configuration. It retains the internal target, rules,
external labels and unrelated scrape jobs, adds verified mTLS with a dedicated
core client identity, and migrates any static scrape of that same target.
Unexpected targets, mixed scrape jobs, dynamic discovery or existing
authentication/trust configurations are rejected for inspection.

The opt-in Compose overlay adds only three read-only file mounts. It does not
replace the current Prometheus image, command, configuration bind or state.
The configured server SNI is alertmanager.core.codestra.internal; server
certificates must cover that SAN. Certificate material is provisioned outside
Git through the platform PKI, readable by the running Prometheus UID.

Record current input hashes, image/state identity, all targets and alert
destinations; validate the candidate with the running image's promtool and
render both merged Compose configurations. Preserve encrypted off-host
Alertmanager backup/restore evidence. Stage client mounts before the cutover,
then apply client/server TLS together and require the core destination active,
all prior targets up, successful notification counters, both provider
destinations active and rejection without a valid certificate. Restore both
sides together on any failure. Preserve the existing single-file bind inode
when updating configuration.

This is a compatibility preparation, not an activation record. It does not
provide certificates, publish a port or switch the legacy receiver to Middleware.
The canonical incident API still requires its own protected signed release,
Keycloak identity, private ingress and durable ingestion verification.
