# Contributing

Use a disposable environment for kernel/network changes. Run pytest, Python lint, shell checks, Ansible syntax/lint and the release tree scan. Add regression tests for security fixes; keep installer defaults, `.env` templates, API roles and UI in agreement.

Do not commit inventories, private keys, live configuration, Terraform state, employee data or logs. Use example.com domains and RFC 5737 addresses in examples. Preserve issued peer keys, REALITY and AWG parameters on repeat deployment. Mutating VPN operations must use the shared backend lock. Never flush an operator's firewall ruleset.

Changes to supported platforms or protocol behavior require real acceptance evidence. Explain the resulting behavior and relevant tests in the pull request.
