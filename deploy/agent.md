# Deployment guidance

Role defaults have lowest precedence. Private overrides are passed last. Repeat installation must preserve keys, peers, administrator token, REALITY and AWG parameters. Load only CorpVPN firewall tables. Keep the panel and Xray backends on loopback, with nginx on the public TLS port. Validate configuration before promotion and service stability before reporting success.
