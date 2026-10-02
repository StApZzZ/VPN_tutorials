# Monitoring

Scrape the panel's HTTPS `/metrics` with a bearer API token whose scope is
`metrics`. Store that token in a mode-0600 file on the Prometheus server and
reference it with `authorization.credentials_file`. Use a trusted CA, including
the gateway's explicitly installed self-signed CA when applicable; do not disable
certificate verification in production.

Install your distribution's `prometheus-node-exporter` on the gateway. Set its
`--collector.textfile.directory=/var/lib/prometheus/node-exporter` and keep its
listener private. The backup and health-check timers write aggregate metrics
there, without users, private keys or tokens. Copy `alerts.yml` into your existing
Prometheus rule_files configuration and reload after `promtool check rules`.

Example scrape job (replace the example hostname and protected credentials path):

```yaml
- job_name: corpvpn
  scheme: https
  authorization:
    type: Bearer
    credentials_file: /etc/prometheus/secrets/corpvpn-token
  static_configs:
    - targets: [vpn.example.com]
```

Route alerts through your organisation's existing Alertmanager. Confirm a test
alert reaches the on-call team. No third-party monitoring account is required.
