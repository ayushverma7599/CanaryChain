# infra/containers

| Image | Source | Used for |
|---|---|---|
| tenant (red, blue, llm) | `tenants/Dockerfile` (one image, `TENANT_NAME` selects the role) | The three isolated tenants. Plants the decoys below. |
| gateway | `gateway/Dockerfile` | The only bridge between tenant networks. |
| canary | `infra/containers/canary/Dockerfile` | Sidecar: `network` mode (one per tenant network) and `host` mode (file watcher + process probe). |

Decoys planted in each tenant (all fake, uniquely tagged):

| Canary | Planted as | Fires when |
|---|---|---|
| credential | `/data/.env` with `API_KEY=CNRY-<red\|blue\|llm>-<32 hex>` | another tenant's token appears in text delivered to a tenant (core path `scan_text`, gateway) |
| file | `/data/.rt_findings.json` (red only) | the file is opened after the watcher is armed (inotify `opened`) |
| network | sidecar listener on port 9999 inside each tenant network | anything connects. Never fires while isolation holds |
| process | `rt_sync_<red\|blue\|llm>` (`exec -a` in `tenants/entrypoint.sh`) | another tenant's decoy name is visible inside a tenant (shared PID namespace) |
