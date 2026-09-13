# Upgrade policy

Resolve an upstream release tag to its exact source commit, multi-platform digest,
and linux/amd64 manifest. Validate all configuration, rules, and tests with that
image, then promote the same protected source through development, test, staging,
production, and main. Never build an image on the target server.
