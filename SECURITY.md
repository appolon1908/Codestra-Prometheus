# Security policy

Report vulnerabilities privately to the repository owner. Never commit target
credentials, authorization headers, private keys, session data, or secret values.

Prometheus native APIs must remain loopback/private, the admin and lifecycle APIs
must remain disabled, images and actions must be immutable, and high-cardinality
or protected identifiers must not become metric labels.
