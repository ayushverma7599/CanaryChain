# Isolation policy

Prevention (this file) is separate from detection (canaries, see `infra/containers/README.md`).
Everything below is enforced in `docker-compose.yml` and checked by `tests/isolation_check.sh`.

| Control | Setting | Effect |
|---|---|---|
| Network segmentation | one `internal: true` network per tenant (`red_net`, `blue_net`, `llm_net`); the gateway is the only service on all three | no direct tenant-to-tenant path, no internet, no host access |
| Capabilities | `cap_drop: [ALL]` | no raw sockets, mounts, chown, ... |
| Filesystem | `read_only: true`, `tmpfs: /tmp` | a tenant cannot modify its own image |
| User | `user: 10001:10001` | no root inside the container |
| Privilege escalation | `no-new-privileges:true` | setuid binaries cannot gain privileges |
| Resource limits (cgroups) | `pids_limit: 128`, `mem_limit: 512m`, `cpus: 0.5` | one tenant cannot starve the others |
| Volumes | one private named volume per tenant | no shared writable storage |
| Syscalls | Docker's default seccomp profile (no override) | blocks dangerous syscalls without breaking tenants |
| Privileged containers | none | |

## Why no custom seccomp profile yet
A custom profile that blocks too much breaks the tenants and loses objective 01 (isolate without breaking function). Start from Docker's default (already active), and only add a tightened profile as `infra/policies/seccomp-tenant.json` after copying Docker's default from the moby repository for the installed Docker version and re-running `tests/isolation_check.sh`.

## Canary service privileges (known limitation)
- `network` sidecars sit on one tenant network each plus the internal `gateway_api` network. They expose only the canary port.
- The `host` sidecar needs the Docker socket (for `docker exec`) and read-only access to the tenant volumes. **Docker socket access is equivalent to root on the host.** Only this one service gets it; it must stay off every tenant network.
- `POST /internal/event` is protected by `INTERNAL_EVENT_TOKEN` (fails closed when unset) and must not be reachable from the browser or tenant networks.
