# Codestra Prometheus

Repository authority for private Codestra metrics collection, recording rules,
alerts, and target catalogues. It uses a verified upstream Prometheus image and a
deterministic signed configuration bundle. Source changes do not deploy production.

All unverified production scrape targets and Blackbox probes remain pending until
staging and runtime certification evidence authorizes an activation change.
