# Kyyow integration

This repository is the source authority for **prometheus** in the Kyyow platform. Its Kyyow boundary is machine-readable in [kyyow-integration.v1.json](kyyow-integration.v1.json).

The component is **private** and its native ports are not made public by this contract. Keycloak owns identity, OpenBao owns secret delivery, and Middleware remains the sole writer to Odoo. Grafana and Superset consume read-only data paths.

This contract is source-complete but deliberately does not claim a live deployment. Production activation requires an immutable image/configuration digest, private-network verification, restore and rollback evidence, and a separately approved cutover.
