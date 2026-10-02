#!/usr/bin/env python3
"""Configure a CorpVPN deployment without executing configuration as shell code."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError(f"invalid configuration line {number}")
        # shlex handles quoting and comments; it never evaluates substitutions.
        parts = shlex.split(value, comments=True, posix=True)
        values[key] = " ".join(parts)
    return values


def write_json(path: Path, value: dict, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def csv(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def main() -> int:
    if "--help" in sys.argv:
        print("Usage: QS_ENV=deploy/quickstart.env bash deploy/quickstart.sh")
        return 0
    path = Path(os.environ.get("QS_ENV", str(HERE / "quickstart.env")))
    if not path.is_file():
        raise ValueError(f"config not found: {path}; copy deploy/quickstart.env.example")
    path.chmod(0o600)
    cfg = read_env(path)
    for key in ("SERVER_A_IP", "SSH_KEY"):
        if not cfg.get(key):
            raise ValueError(f"{key} is required")
    host, user = cfg["SERVER_A_IP"], cfg.get("SSH_USER") or "root"
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", host) or not re.fullmatch(r"[a-zA-Z0-9_-]+", user):
        raise ValueError("invalid SSH host or username")
    key = Path(cfg["SSH_KEY"].replace("${HOME}", str(Path.home())).replace("$HOME", str(Path.home()))).expanduser().resolve()
    if not key.is_file():
        raise ValueError(f"SSH key not found: {key}")
    protocols = csv(cfg.get("PROTOCOLS") or "wg,awg,vless")
    if not protocols or set(protocols) - {"wg", "awg", "vless"}:
        raise ValueError("PROTOCOLS must list wg, awg and/or vless")
    corp, dns = csv(cfg.get("CORP_CIDRS", "")), csv(cfg.get("CORP_DNS", ""))
    for network in corp:
        if ipaddress.ip_network(network, strict=False).version != 4:
            raise ValueError("CORP_CIDRS must contain IPv4 networks")
    for address in dns:
        if ipaddress.ip_address(address).version != 4:
            raise ValueError("CORP_DNS must contain IPv4 addresses")
    connector = cfg.get("SERVER_B_IP", "")
    if connector and (not corp or not re.fullmatch(r"[a-zA-Z0-9.-]+", connector)):
        raise ValueError("split mode needs valid SERVER_B_IP and CORP_CIDRS")
    name = cfg.get("PANEL_FQDN") or cfg.get("SERVER_A_DOMAIN") or host
    tls = cfg.get("TLS_MODE") or "auto"
    if tls == "auto":
        tls = "letsencrypt" if cfg.get("PANEL_FQDN") and cfg.get("CERTBOT_EMAIL") else "selfsigned"
    if tls not in {"selfsigned", "letsencrypt", "custom", "none"}:
        raise ValueError("TLS_MODE must be auto, letsencrypt, selfsigned, custom or none")
    if tls == "letsencrypt" and not (cfg.get("PANEL_FQDN") and cfg.get("CERTBOT_EMAIL")):
        raise ValueError("letsencrypt needs PANEL_FQDN and CERTBOT_EMAIL")
    if tls == "custom":
        for k in ("TLS_CERT_FILE", "TLS_KEY_FILE"):
            if not Path(cfg.get(k, "")).is_file():
                raise ValueError(f"custom TLS needs {k}")
    public_url = cfg.get("PANEL_PUBLIC_URL", "")
    trusted = csv(cfg.get("TRUSTED_PROXY_CIDRS", ""))
    for network in trusted:
        ipaddress.ip_network(network, strict=False)
    if tls == "none":
        parsed = urlsplit(public_url)
        if not trusted or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("TLS_MODE=none requires TRUSTED_PROXY_CIDRS and an HTTPS PANEL_PUBLIC_URL")
    auth_mode = cfg.get("AUTH_MODE") or "local"
    if auth_mode not in {"local", "oidc", "ldap"}:
        raise ValueError("AUTH_MODE must be local, oidc or ldap")
    enabled = {"oidc": auth_mode == "oidc" or cfg.get("OIDC_ENABLED", "").lower() == "true",
               "ldap": auth_mode == "ldap" or cfg.get("LDAP_ENABLED", "").lower() == "true"}
    required = {"oidc": ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET"),
                "ldap": ("LDAP_URL", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_USER_BASE_DN")}
    for provider, on in enabled.items():
        if on:
            for k in required[provider]:
                if not cfg.get(k):
                    raise ValueError(f"{provider} needs {k}")
    insecure_oidc = cfg.get("OIDC_ALLOW_INSECURE_HTTP", "").lower() == "true"
    if enabled["oidc"] and not (cfg["OIDC_DISCOVERY_URL"].startswith("https://") or insecure_oidc):
        raise ValueError("OIDC requires HTTPS; OIDC_ALLOW_INSECURE_HTTP=true is for isolated labs only")
    if enabled["ldap"] and not (cfg["LDAP_URL"].startswith("ldaps://") or cfg.get("LDAP_START_TLS") == "true"):
        raise ValueError("LDAP requires LDAPS or LDAP_START_TLS=true")
    ca = cfg.get("LDAP_CA_FILE", "")
    if ca and not Path(ca).is_file():
        raise ValueError("LDAP_CA_FILE not found")
    ansible = HERE / "ansible"
    secret_path = ansible / "group_vars/all.secrets.yml"
    saved = {}
    if secret_path.exists():
        try:
            saved = json.loads(secret_path.read_text())
        except ValueError:
            # Older installer files are YAML; use Ansible's installed YAML parser.
            import yaml
            saved = yaml.safe_load(secret_path.read_text()) or {}
    token = cfg.get("PANEL_SECRET_TOKEN", "")
    generated = False
    if token in ("", "replace-with-long-random-token"):
        token = saved.get("panel_secret_token", "")
    if not token:
        # Recover from the host if the controller lost its generated files.
        probe = "import pathlib,shlex; p=pathlib.Path('/opt/vpn-panel/.env'); print(next((' '.join(shlex.split(x.split('=',1)[1], comments=True)) for x in p.read_text().splitlines() if x.startswith('PANEL_SECRET_TOKEN=')), '') if p.exists() else '')"
        argv = ["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=20", f"{user}@{host}"]
        cmd = (["sudo", "-n"] if user != "root" else []) + ["python3", "-c", probe]
        result = subprocess.run(argv + [shlex.join(cmd)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError("SSH or passwordless sudo failed on gateway")
        token = result.stdout.strip()
    if not token:
        token, generated = secrets.token_urlsafe(32), True
    url = public_url.rstrip("/") if tls == "none" else "https://" + name
    variables = {
        "vpn_panel_server_name": name, "vpn_panel_nginx_server_name": name,
        "vpn_panel_public_host": host, "vpn_panel_fallback_host": host,
        "vpn_panel_wg_endpoint_host": name, "vpn_panel_public_url": url,
        "vpn_panel_enabled_protocols": protocols, "vpn_panel_dns_servers": dns or ["1.1.1.1", "1.0.0.1"],
        "vpn_panel_corp_cidrs": corp, "vpn_panel_network_policy_mode": "enforce",
        "vpn_panel_tls_mode": tls, "vpn_panel_tls_self_signed": tls == "selfsigned",
        "vpn_panel_certbot_email": cfg.get("CERTBOT_EMAIL", ""),
        "vpn_panel_xray_client_reality_server_name": cfg.get("REALITY_SERVER_NAME") or "www.cloudflare.com",
        "vpn_panel_oidc_enabled": enabled["oidc"], "vpn_panel_oidc_allow_insecure_http": insecure_oidc, "vpn_panel_ldap_enabled": enabled["ldap"],
    }
    if tls != "none":
        variables.update({"vpn_panel_ssl_cert_path": f"/etc/letsencrypt/live/{name}/fullchain.pem" if tls == "letsencrypt" else "/etc/vpn-panel/tls/fullchain.pem",
                          "vpn_panel_ssl_key_path": f"/etc/letsencrypt/live/{name}/privkey.pem" if tls == "letsencrypt" else "/etc/vpn-panel/tls/privkey.pem"})
    if tls == "custom":
        variables.update(vpn_panel_tls_cert_src=str(Path(cfg["TLS_CERT_FILE"]).resolve()), vpn_panel_tls_key_src=str(Path(cfg["TLS_KEY_FILE"]).resolve()))
    for k in ("AUTH_ADMIN_GROUPS", "AUTH_OPERATOR_GROUPS", "AUTH_USER_GROUPS", "TRUSTED_PROXY_CIDRS", "AUTH_LOCAL_ALLOWED_CIDRS"):
        variables["vpn_panel_" + k.lower()] = csv(cfg.get(k, ""))
    for k in ("WG_NETWORK", "AWG_NETWORK", "WG_PORT", "AWG_PORT"):
        if cfg.get(k):
            variables["vpn_panel_" + k.lower()] = int(cfg[k]) if k.endswith("PORT") else cfg[k]
    for k in ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_BUTTON_LABEL", "LDAP_URL", "LDAP_BIND_DN", "LDAP_USER_BASE_DN"):
        if cfg.get(k):
            variables["vpn_panel_" + k.lower()] = cfg[k]
    for k in ("AUTH_LOCAL_TOTP", "LDAP_USER_FILTER", "LDAP_USERNAME_ATTR", "LDAP_DISPLAY_NAME_ATTR", "LDAP_GROUP_BASE_DN", "LDAP_GROUP_SEARCH_FILTER", "LDAP_GROUP_ATTR", "LDAP_DISABLED_FILTER", "OIDC_GROUPS_CLAIMS", "OIDC_USERNAME_CLAIMS"):
        if cfg.get(k):
            variables["vpn_panel_" + k.lower()] = cfg[k]
    if cfg.get("SITE_LAN_INTERFACE"):
        variables["site_link_lan_iface"] = cfg["SITE_LAN_INTERFACE"]
    variables["vpn_panel_corp_domains"] = csv(cfg.get("CORP_DOMAINS", ""))
    if ca:
        variables["vpn_panel_ldap_ca_src"] = str(Path(ca).resolve())
    variables["vpn_panel_ldap_start_tls"] = cfg.get("LDAP_START_TLS") == "true"
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"):
        if cfg.get(k):
            variables["vpn_panel_" + k.lower()] = cfg[k]
    secret_vars = {"panel_secret_token": token,
                   "vpn_panel_oidc_client_secret": cfg.get("OIDC_CLIENT_SECRET", ""),
                   "vpn_panel_ldap_bind_password": cfg.get("LDAP_BIND_PASSWORD", ""),
                   "vpn_panel_xray_reality_private_key": cfg.get("SERVER_A_REALITY_PRIVATE_KEY", ""),
                   "vpn_panel_xray_reality_short_id": cfg.get("SERVER_A_REALITY_SHORT_ID", "")}
    gateway = {"ansible_host": host, "ansible_user": user, "ansible_ssh_private_key_file": str(key)}
    children = {"management": {"hosts": {"server-a": gateway}}}
    if connector:
        connector_key = Path(cfg.get("SERVER_B_SSH_KEY") or str(key)).expanduser().resolve()
        if not connector_key.is_file():
            raise ValueError("SERVER_B_SSH_KEY not found")
        children["site_connector"] = {"hosts": {"server-b": {"ansible_host": connector, "ansible_user": user, "ansible_ssh_private_key_file": str(connector_key)}}}
    inventory = ansible / "inventory/hosts.yml"
    write_json(inventory, {"all": {"children": children}})
    write_json(ansible / "group_vars/all.yml", variables)
    write_json(secret_path, secret_vars)
    runner = os.environ.get("QS_RUN_SH", str(HERE / "run.sh"))
    command = ["bash", runner, "--inventory", str(inventory), "--ssh-key", str(key), "--ssh-user", user]
    subprocess.run(command, check=True)
    if connector:
        subprocess.run(command + ["--playbook", "site-connector.yml"], check=True)
    print(f"Quickstart complete!\nPanel: {url}/\nEmployees: {url}/me")
    print(f"Break-glass admin: token saved in {secret_path}")
    if generated:
        print("A new token was generated; read it from the protected secrets file.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"quickstart: {exc}", file=sys.stderr)
        sys.exit(1)
