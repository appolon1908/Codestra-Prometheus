# Codestra Prometheus corporate runbooks

These runbooks are source-side response guides. They do **not** authorize deployment, secret retrieval, customer-data access, live trading, message delivery, dialing, or cross-business access. Preserve incident IDs, exact deployment SHAs, business scope, timestamps, and evidence links in the governed incident path.

## CodestraWatchdog

1. Confirm the alert is continuously firing in Prometheus.
2. Confirm Alertmanager receives and groups it under the watchdog route.
3. Confirm Middleware records the governed event without sending customer communications.
4. If any stage is missing, treat the alerting control plane as degraded and stop release promotion.

## CodestraTargetDown

1. Confirm the failing target, environment, server, and last successful scrape.
2. Check network reachability and the exporter/service `/metrics` endpoint from the Prometheus network.
3. Check the exact deployed image digest and recent deployment annotations.
4. Do not bypass Kong, Caddy, mTLS, or firewall policy to restore a scrape.
5. Escalate to the target owner when the exporter is healthy but the application is not.

## CodestraBlackboxProbeFailed

1. Re-run the approved module from the Blackbox network; do not add credentials or authorization headers.
2. Check DNS resolution, TLS verification, HTTP status, redirect policy, and probe duration.
3. Compare against a second resolver/network only after preserving the original evidence.
4. Confirm the target is an approved inventory endpoint and not customer-specific.

## CodestraPrometheusReloadFailed

1. Inspect the reload timestamp and Prometheus logs for the rejected file and exact error.
2. Run `promtool check config` and `promtool check rules` against the exact deployed commit.
3. Keep the last-known-good configuration active; do not force a partial reload.
4. Correct through a reviewed branch and re-run exact-head CI.

## CodestraSLOFastBurn

1. Identify the affected business, application, service, environment, and deployment.
2. Correlate error ratio, latency, dependency health, traces, logs, and deployment changes.
3. Determine customer impact without placing customer IDs in labels or incident titles.
4. Halt promotion and use the service rollback/run-forward authority when the latest change is causal.
5. Beyvra monitoring may inspect safe health and reconciliation state only; it cannot authorize or execute trades.

## CodestraSLOSustainedBurn

1. Confirm traffic volume is sufficient and the SLO target gauge is current.
2. Segment by bounded operation, dependency, provider, and deployment dimensions.
3. Open a service-owner corrective action before the remaining error budget becomes unsafe.

## CodestraQueueSaturation

1. Check queue depth, configured capacity, arrival rate, worker throughput, and oldest-message age.
2. Check downstream dependency latency and worker failures before scaling.
3. Confirm idempotency, inbox, and outbox guarantees remain intact.
4. Do not purge, replay, or move messages across businesses without a separate approved recovery procedure.

## CodestraWorkerFailures

1. Identify the bounded worker class, exact deployment, exception category, and downstream dependency.
2. Confirm retries are bounded and dead-letter/inbox/outbox state remains durable.
3. Stop a poison-message loop without deleting evidence or exposing payload contents.

## CodestraContainerOOM

1. Confirm the container, server, memory limit, working set, and restart count.
2. Correlate with request volume, queue growth, deployment, and garbage-collection metrics.
3. Capture a safe profile only under the service security policy; never dump secrets or customer payloads.
4. Adjust limits or code through an immutable reviewed release.

## CodestraRedisUnavailable

1. Confirm the dedicated exporter can reach the private Redis address using its read-only ACL.
2. Check Redis process state, TLS/ACL errors, replication role, persistence, and host saturation.
3. Do not place credentials in a target URI and do not enable the multi-target scrape endpoint.

## CodestraRedisEvictions

1. Confirm `maxmemory`, eviction policy, memory utilization, fragmentation, and workload role.
2. Determine whether cache, queue, session, rate-limit, workflow, or realtime data is affected.
3. Never inspect or export raw key names to diagnose aggregate eviction pressure.

## CodestraBackupStale

1. Verify the controlled status-file producer, backup job result, destination, checksum, and retention evidence.
2. Confirm the metric is in Unix seconds and has not been manually edited.
3. Run the approved backup repair without overwriting the last-known-good artifact.

## CodestraRestoreValidationStale

1. Confirm the last isolated restore validation, checksum verification, application smoke result, and measured RTO.
2. Schedule an isolated validation against a non-production destination.
3. Never restore over a live database merely to clear the alert.

## CodestraConfigurationDrift

1. Identify the exact source commit, deployed digest, rendered configuration checksum, and changed paths.
2. Preserve the deployed copy as evidence.
3. Reconcile by reviewed Git change or approved rollback; never silently copy server state into production authority.

## CodestraCertificateExpiringSoon

1. Identify the bounded certificate class, issuer, SANs, owner, and renewal mechanism.
2. Confirm the OpenBao/ACME renewal job and deployment path without exposing private keys.
3. Renew and validate in staging before production promotion.

## CodestraCertificateExpiringCritical

1. Escalate immediately to platform security and the affected service owner.
2. Prepare renewal and traffic-continuity evidence.
3. Never disable TLS verification or substitute an unreviewed certificate.

## CodestraProbeCertificateExpiringSoon

1. Confirm Blackbox observed the canonical endpoint and full verified chain.
2. Check authoritative DNS and the active edge certificate, not a local cached copy.
3. Renew through the owning edge repository and verify the new chain externally.
