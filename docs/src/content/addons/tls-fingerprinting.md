---
title: "TLS Fingerprinting"
weight: 6
aliases:
  - /tls-fingerprinting/
---

# TLS Fingerprinting

mitmproxy computes JA3 and JA4 fingerprints directly from the intercepted
TLS ClientHello. Fingerprints are cached per client connection, so requests
reusing an existing TLS connection do not trigger another calculation.

The `tls_fingerprint` addon evaluates these fingerprints against rules keyed by
User-Agent prefix. A client starts with a score of 100. Matching an expected
fingerprint deducts no points; a missing or unexpected fingerprint deducts the
configured weight. If the resulting score is below the threshold, mitmproxy
returns HTTP 403.

## Rules

Rules are loaded from a YAML file configured with
`tls_fingerprint_rules`. The same fingerprint type may list multiple accepted
values. Replace the example fingerprints below with values observed from your
known-good clients.

```yaml
threshold: 80
weights:
  ja3: 25
  ja4: 25

rules:
  - name: chrome
    user_agent_prefix: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"
    ja3:
      - "20dd18bdd3209ea718989030a6f93364"
    ja4:
      - "t12d1711h2_67e6df579eba_de5ccbe16bdd"
```

The threshold and weights may also be set per rule:

```yaml
rules:
  - name: chrome
    user_agent_prefix: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"
    fingerprints:
      ja3: ["20dd18bdd3209ea718989030a6f93364"]
    weights:
      ja3: 40
```

The longest matching `user_agent_prefix` wins. Requests whose User-Agent does
not match any rule are not blocked. The top-level `threshold` defaults to 80,
and JA3/JA4 each default to a weight of 25.

## Options

The addon is enabled by default, but it does nothing until a rules file is
configured.

| Option | Default | Description |
| --- | --- | --- |
| `tls_fingerprint_rules` | unset | Path to the YAML rules file. Changes are hot-reloaded without blocking the event loop. |
| `tls_fingerprint_threshold` | unset | Overrides the threshold from the rules file. |
| `tls_fingerprint_enabled` | `true` | Enables fingerprint calculation and rule evaluation. |
| `tls_fingerprint_block` | `true` | Enables the HTTP 403 response. When disabled, fingerprints and scores are still recorded. |

For example:

```bash
mitmdump --set tls_fingerprint_rules=./tls-fingerprint-rules.yaml
```

## Metadata

Every HTTP flow with a cached TLS fingerprint records its result in
`flow.metadata`. The `tls_fingerprint` key contains `ja3`, `ja4`, the raw
fingerprints, `score`, `threshold`, `matched_rule`, `reason`, and `blocked`.
These values are also available as the flat keys `ja3`, `ja4`,
`fingerprint_score`, `fingerprint_rule`, `fingerprint_reason`, and
`fingerprint_blocked`.

They can be inspected with the usual metadata filters or by selecting a flow in
the interactive UI.

## Hot Reloading

While mitmproxy is running, the addon polls the rules file for modification
time changes. Reading and parsing the YAML happens in a worker thread, so a
slow disk or a large rules file does not block the proxy event loop. If a
reload fails, the previous valid rules stay active and a warning is logged.
