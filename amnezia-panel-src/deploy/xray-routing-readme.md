# Xray Routing Integration

## Goal

Panel-generated routing rules are exported into a standalone JSON fragment and then merged into the live Xray config on the ingress host before validation and reload.

## Files

- `xray-ingress-example.json` — base config template for the primary/ingress node
- `xray-egress-example.json` — base config template for the egress/relay node
- `routing.generated.json` — panel-generated fragment written to `XRAY_ROUTING_EXPORT_PATH`
- `config.generated.json` — panel-generated merged config written to `XRAY_MERGED_CONFIG_EXPORT_PATH`
- `xray_action_state.json` — last `export/validate/reload/apply` result written to `XRAY_ACTION_STATE_PATH`
- `XRAY_APPLY_BACKUP_DIR` — directory for live config backups before `Apply + Reload`
- `xray_clients.json` — panel-managed VLESS clients written to `XRAY_CLIENTS_PATH`

## Expected Environment on the Panel Host

Set these variables in `/opt/vpn-panel/.env`:

```env
XRAY_ROUTING_EXPORT_PATH=/etc/xray/routing.generated.json
XRAY_MERGED_CONFIG_EXPORT_PATH=/etc/xray/config.generated.json
XRAY_BASE_CONFIG_PATH=/etc/xray/config.json
XRAY_ACTION_STATE_PATH=/etc/vpn-panel/xray_action_state.json
XRAY_APPLY_BACKUP_DIR=/var/backups/vpn-panel/xray
XRAY_VALIDATE_COMMAND=/usr/local/bin/xray run -test -config {config_path}
XRAY_RELOAD_COMMAND=/bin/systemctl reload xray
XRAY_CLIENTS_PATH=/etc/vpn-panel/xray_clients.json
XRAY_CLIENT_INBOUND_TAG=vless-in
XRAY_CLIENT_SERVER=vpn.example.com
XRAY_CLIENT_PORT=443
XRAY_CLIENT_NETWORK=tcp
XRAY_CLIENT_SECURITY=reality
XRAY_CLIENT_LOCAL_SOCKS_PORT=10808
XRAY_CLIENT_LOCAL_HTTP_PORT=10809
XRAY_CLIENT_REALITY_SERVER_NAME=www.microsoft.com
XRAY_CLIENT_REALITY_PUBLIC_KEY=REPLACE_WITH_INGRESS_REALITY_PUBLIC_KEY
XRAY_CLIENT_REALITY_SHORT_ID=REPLACEWITHHEX
XRAY_CLIENT_FINGERPRINT=chrome
XRAY_CLIENT_FLOW=
```

If `xray` is installed in another path, update `XRAY_VALIDATE_COMMAND`.

## Workflow

1. Fill `xray-ingress-example.json` with real UUIDs, REALITY keys and fingerprints, then save as the live base config at `XRAY_BASE_CONFIG_PATH`.
2. In the panel:
   - Create VLESS clients in the `Xray / VLESS clients` section.
   - Give users the `vless://` link, QR code, or full Xray client JSON from that section.
   - Define routing overrides for direct and relay paths as needed.
   - Click `Export` to write both `routing.generated.json` and `config.generated.json`.
   - Click `Validate` to validate the persisted merged config.
   - Click `Reload Xray` only when Xray is already configured to read the generated config path.
   - Click `Apply + Reload` to back up `XRAY_BASE_CONFIG_PATH`, replace it with `config.generated.json`, and reload Xray.
3. Use `Preview merged`, `Exported routing`, and `Exported merged` downloads to compare the current preview with what is already stored on disk.
4. Check the `Xray doctor` block before manual smoke: it should have no red checks for VLESS settings, enabled clients, base config, and validate/reload commands.

## Notes

- The panel owns only the `routing` section in this flow.
- The panel owns VLESS clients for the inbound tagged by `XRAY_CLIENT_INBOUND_TAG`.
- Inbounds, outbounds and REALITY private keys still belong to the base config.
- REALITY public connection parameters for client share links come from `XRAY_CLIENT_*` settings.
- A relay/egress node should expose a dedicated VLESS inbound for the ingress uplink.
- Runtime status in the dashboard also shows whether the exported artifacts are in sync with the current preview and what happened during the last Xray action.
- Xray doctor is read-only. It does not export, validate, apply, or reload anything by itself; it only shows blockers and warnings before manual smoke.
- If `Apply + Reload` fails during reload, the panel restores the live config from the backup it just created.
