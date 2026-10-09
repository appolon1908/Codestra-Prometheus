# Codestra Prometheus login visual contract

## Purpose

Prometheus does not own a Codestra user-password screen. In the current Codestra architecture its native UI remains private and its listener is bound to loopback by default. The shared Codestra login appearance therefore belongs at an approved browser authentication gateway, not inside Prometheus and not on a newly exposed public port.

## Visual contract

Any approved human browser gateway in front of Prometheus must use the shared Codestra Keycloak identity surface and the black-and-white design language established by `ingtrader21-spec/social.codestra.co`:

- page background: `#0b0b0b`;
- auth panel: `#171717`;
- primary text and CTA: white;
- secondary text: `#a1a1aa`;
- subtle white borders;
- 16 px panel radius and 10 px controls;
- visible keyboard focus and reduced-motion support;
- no Starlink branding, images or copied assets.

The shared identity implementation is owned by `ingtrader21-spec/Keycloak`. A gateway may redirect users to that identity surface, but it must not collect a Codestra password itself.

## Exposure and identity boundary

The existing Prometheus service remains private. This visual contract does **not** authorize `prom.codestra.media` as a public Caddy route, public DNS exposure, a public native `:9090` listener, or a new interactive Keycloak client.

The existing `monitoring-readonly` Keycloak identity is a machine/service identity with standard browser flow disabled. It must not be repurposed as an interactive user client. If human browser access is later approved, it requires a separately reviewed browser client, explicit roles/MFA, private-network policy, callback allowlist and gateway deployment.

The visual change must never:

- enable anonymous public Prometheus access;
- add local password handling to Prometheus;
- expose service-account credentials to a browser;
- bypass Caddy/private-network controls;
- weaken Prometheus query, retention or read-only runtime safeguards.

## Acceptance

Source-level acceptance requires the shared Keycloak identity theme to implement the Codestra black-and-white visual contract while Prometheus remains private-only.

Production visual acceptance requires an approved private browser route plus rendered authenticated captures at desktop and narrow widths. Until such a route exists, no claim of a live Prometheus login screen should be made.
