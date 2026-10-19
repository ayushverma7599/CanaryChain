# CanaryChain

**Tamper-evident canary detection for multi-tenant AI red/blue-team environments.**

Three tenants (**red** team, **blue** team, **llm**) share one machine. CanaryChain isolates them, plants decoy "canaries" that no honest tenant would ever touch, detects when one is touched, classifies the event (MITRE ATLAS), scores its severity, and writes it to a **hash-chained audit log** that shows tampering.

This README is a complete guide to set up, run, test and demo the project on **Windows** (and Linux/macOS). Follow it top to bottom.

---

## Table of contents

1. [What this project does](#1-what-this-project-does)
2. [Current status](#2-current-status)
3. [Architecture](#3-architecture)
4. [Prerequisites](#4-prerequisites)
5. [Windows setup (step by step)](#5-windows-setup-step-by-step)
6. [Linux / Kali / macOS setup](#6-linux--kali--macos-setup)
7. [Run the project](#7-run-the-project)
8. [Verify isolation (test suite)](#8-verify-isolation-test-suite)
9. [Demo script (for judges)](#9-demo-script-for-judges)
10. [How the isolation works (explained)](#10-how-the-isolation-works-explained)
11. [Component reference](#11-component-reference)
12. [Design: canaries, severity, hash chain](#12-design-canaries-severity-hash-chain)
13. [Command cheat sheet](#13-command-cheat-sheet)
14. [Troubleshooting](#14-troubleshooting)
15. [Known limitations (honest list)](#15-known-limitations-honest-list)
16. [Team](#16-team)

---

## 1. What this project does

| Judging objective | How CanaryChain addresses it |
|---|---|
| **01. Isolate without breaking function** | Each tenant runs in its own hardened container on its own internal network. They cannot reach each other, the internet, or the host, yet still do their work through a gateway. |
| **02. Detect boundary violations** | Canaries (decoy credentials, files, network listeners, processes) fire when a tenant crosses a boundary. The gateway also flags one tenant's token appearing in another's traffic. |
| **03. Trustworthy evidence** | Every alert is classified, severity-scored with a formula a human can recompute, and appended to a hash-chained log. Editing any past entry breaks verification. |

**Core design rule:** *the thing that detects must not be controllable by the thing being watched.* Detectors and the audit log live outside the tenants, so a tenant cannot kill or edit them.

---

## 2. Current status

| Component | Owner | Status |
|---|---|---|
| Isolation baseline (hardened Compose, internal networks) | Ayush | Done, 11/11 tests pass |
| Gateway (the only path between tenants, source-IP attribution) | Ayush | Done |
| Stub LLM tenant | Ayush | Done |
| Break-it demo scenarios + false-alarm baseline | Ayush | Done |
| Canary agents (credential, file, network, process) | Harshit | In progress |
| Collector API, classifier, scoring, hash chain, `verify_chain.py` | Aditya | In progress |
| Dashboard | Aditya | In progress |

> Update this table as parts are merged. Sections marked *(planned)* below describe components that are not in the repository yet.

---

## 3. Architecture

```
                     ┌──────────────────────── host (your PC) ───────────────────────┐
                     │                                                                │
   curl / demo ────► │  127.0.0.1:8080                                                │
                     │        │                                                       │
                     │   ┌────▼─────┐   mgmt network (only the gateway is on it)     │
                     │   │ gateway  │                                                 │
                     │   └─┬──┬──┬──┘                                                 │
                     │     │  │  │  the gateway is the ONLY thing on all 3 networks   │
                     │  red_net blue_net llm_net     (all `internal: true`:           │
                     │     │     │      │             no internet, no host, no bridge) │
                     │  ┌──▼─┐ ┌─▼──┐ ┌─▼──┐                                         │
                     │  │red │ │blue│ │llm │   hardened tenant containers            │
                     │  └────┘ └────┘ └────┘                                         │
                     │                                                                │
                     │  (planned) canary agents + collector + dashboard               │
                     └────────────────────────────────────────────────────────────────┘
```

Key point: `red` and `blue` have **no direct route** to each other. Every cross-tenant call goes `tenant → gateway → tenant`, and the gateway logs who called whom.

### Repository layout

```
CanaryChain/
├── docker-compose.yml        # tenants, networks, hardening, gateway
├── .gitattributes            # forces LF line endings (important on Windows)
├── tenants/
│   ├── Dockerfile            # one image used for red, blue and llm
│   ├── entrypoint.sh         # starts the decoy process, then the app
│   └── tenant.py             # tiny HTTP workload + decoy planting (+ stub LLM for 'llm')
├── gateway/
│   ├── Dockerfile
│   └── gateway.py            # routing, source-IP attribution, token scanning
├── tests/
│   └── isolation_check.sh    # proves isolation AND that tenants still work
├── demo/
│   ├── breakit.sh            # deliberately breaks isolation (leak / network)
│   └── normal_traffic.sh     # normal activity: canaries must stay silent
└── (planned) agents/  collector/  dashboard/  verify_chain.py
```

---

## 4. Prerequisites

| Need | Why |
|---|---|
| Windows 10 (22H2+) or Windows 11, 64-bit | Docker Desktop with WSL 2 |
| Virtualization enabled in BIOS/UEFI | WSL 2 and Docker need it (usually on by default) |
| 8 GB RAM recommended, 10 GB free disk | Images and containers |
| Internet for the first build | Downloads the Python base image once |
| Admin rights (once) | To install WSL and Docker Desktop |

You do **not** need to install Python, Node, or anything else on Windows itself. Everything runs inside containers.

---

## 5. Windows setup (step by step)

> **Why WSL 2?** The project's scripts are Linux shell scripts, and the file-canary relies on Linux file events (inotify). Running everything inside WSL 2 (an Ubuntu environment built into Windows) makes it behave identically to Linux. **Do all project commands inside the Ubuntu (WSL) terminal, not in PowerShell or CMD.**

### Step 1: Install WSL 2 with Ubuntu

Open **PowerShell as Administrator** (Start → type `PowerShell` → right-click → *Run as administrator*):

```powershell
wsl --install -d Ubuntu
```

Restart the PC when asked. After the restart an **Ubuntu** window opens and asks you to create a Linux username and password. Choose anything and remember it.

Check that it is WSL 2:

```powershell
wsl -l -v
```

The `VERSION` column for Ubuntu must say `2`. If it says `1`:

```powershell
wsl --set-version Ubuntu 2
```

If `wsl --install` fails with a virtualization error, enable **Intel VT-x / AMD-V (SVM)** in your BIOS and try again.

### Step 2: Install Docker Desktop

1. Download **Docker Desktop for Windows** from https://www.docker.com/products/docker-desktop/ and install it. Keep **"Use WSL 2 instead of Hyper-V"** ticked.
2. Start Docker Desktop and wait until the whale icon says **"Engine running"**.
3. Open **Docker Desktop → Settings → Resources → WSL Integration**, switch on **Enable integration with my default WSL distro** and switch on **Ubuntu**. Click **Apply & Restart**.

### Step 3: Verify Docker inside Ubuntu

Open the **Ubuntu** app from the Start menu (this is your terminal for everything below):

```bash
docker --version
docker compose version
docker run --rm hello-world
```

You should see versions printed and a "Hello from Docker!" message. If `docker` is not found, recheck Step 2.3 (WSL integration for Ubuntu).

### Step 4: Get the code (inside Ubuntu, in your Linux home folder)

```bash
cd ~
git clone https://github.com/ayushverma7599/CanaryChain.git
cd CanaryChain
```

> **Important:** clone into `~` (the Linux filesystem), **not** into `/mnt/c/...` (your Windows drive). Windows drives are slow, break Linux file events, and can corrupt line endings.
> If the repository is private, ask Ayush to add your GitHub account under *Settings → Collaborators*. When Git asks for a password, paste a **personal access token** (GitHub → Settings → Developer settings → Personal access tokens), not your account password.

### Step 5: Make sure scripts are executable

```bash
chmod +x tests/isolation_check.sh demo/breakit.sh demo/normal_traffic.sh tenants/entrypoint.sh
```

Then continue with [Run the project](#7-run-the-project).

### Optional: edit files from Windows

Open VS Code on Windows, install the **WSL** extension, then from the Ubuntu terminal inside the project folder run:

```bash
code .
```

---

## 6. Linux / Kali / macOS setup

**Kali / Debian / Ubuntu:**

```bash
sudo apt update
sudo apt install -y docker.io docker-compose curl git unzip
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker                 # or log out and back in
docker compose version        # if only `docker-compose` exists, see Troubleshooting
git clone https://github.com/ayushverma7599/CanaryChain.git
cd CanaryChain
chmod +x tests/isolation_check.sh demo/breakit.sh demo/normal_traffic.sh tenants/entrypoint.sh
```

**macOS:** install Docker Desktop, then the same `git clone` and `chmod` commands in Terminal.

---

## 7. Run the project

All commands from the `CanaryChain` folder, in the Ubuntu/Linux terminal.

### Build and start

```bash
docker compose up -d --build
```

- `up` creates networks, volumes and containers.
- `-d` runs them in the background.
- `--build` builds the images. The first run downloads the Python base image and takes a few minutes; later runs take seconds.

### Check it is running

```bash
docker compose ps
```

Expected: `red`, `blue`, `llm` and `gateway` are `Up`, and the three tenants show `(healthy)` after about 15 seconds. The gateway shows `127.0.0.1:8080->8080/tcp`.

### Quick manual check

```bash
curl -s localhost:8080/red/health
```

Expected: `{"tenant": "red", "ok": true}`. That request went host → gateway → red.

### Stop and clean up

```bash
docker compose down        # stop and remove containers (keeps data volumes)
docker compose down -v     # also delete volumes: a fully fresh start
```

---

## 8. Verify isolation (test suite)

```bash
./tests/isolation_check.sh
```

Expected final line: `passed=11 failed=0`.

| Check | What it proves |
|---|---|
| red cannot reach blue directly | Tenant networks are separated |
| blue cannot reach red directly | Same, other direction |
| red cannot reach internet | `internal: true` blocks outbound traffic |
| red can reach gateway | The one allowed path works |
| red→blue works through the gateway | Isolation does not break function (objective 01) |
| tenant `/work` still functions | The tenant really does work while hardened |
| runs as non-root (uid 10001) | No root inside the container |
| root filesystem is read-only | A tenant cannot modify its own system files |
| `/data` is writable | Tenants can still write to their own volume |
| decoy process `rt_sync_daemon` exists | The process canary decoy is planted |
| gateway attributes by IP, not header | A tenant cannot lie about who it is |

### False-alarm baseline

Normal activity must produce **no** alerts:

```bash
./demo/normal_traffic.sh 120          # 120 seconds of normal tenant activity
docker compose logs --since 3m gateway | grep -c 'tokens_seen": \["'    # expect 0
docker compose logs --since 3m gateway | grep -c spoof_claimed          # expect 0
```

---

## 9. Demo script (for judges)

Run these in order. Each step maps to a judging objective.

### Step 0: Fresh start

```bash
docker compose down -v && docker compose up -d --build
```

### Step 1: Clean run (objective 01)

```bash
./tests/isolation_check.sh
./demo/normal_traffic.sh 20
```

Say: each tenant is on its own internal network, non-root, read-only, all Linux capabilities dropped, no internet. Tenants still work, and normal traffic raises zero alerts.

### Step 2: Credential leak (objectives 02 and 03)

```bash
./demo/breakit.sh leak
docker compose logs gateway | tail -3
```

What happens: the stub LLM is armed to echo **red's secret token** into a reply to **blue**. The gateway log line shows `"actor": "blue"` and `"tokens_seen": ["red"]`: red's token appeared in a response to blue.

**Spoof test** (if asked "what if blue lies about who it is?"):

```bash
docker compose exec -T blue python -c "import urllib.request as u;u.urlopen(u.Request('http://gateway:8080/red/health',headers={'X-Tenant':'red'}),timeout=3)"
docker compose logs gateway | tail -1
```

The log keeps `"actor": "blue"` and adds `"spoof_claimed": "red"`. The gateway identifies callers by **source IP**, never by what they claim.

### Step 3: Network breach (objective 02)

```bash
./demo/breakit.sh net
docker compose exec blue python -c "import urllib.request as u;print(u.urlopen('http://red:8000/health',timeout=3).read())"
```

blue now reaches red directly, because we deliberately attached blue to red's network. With correct isolation this never happens. Restore it:

```bash
./demo/breakit.sh net-undo
./tests/isolation_check.sh      # back to 11/11
```

### Step 4: Tamper evidence (objective 03) *(planned, needs the collector)*

Edit one old audit-log line, click **Verify chain** on the dashboard (or run `python verify_chain.py`). Verification fails and names the broken entry.

---

## 10. How the isolation works (explained)

Everything is in `docker-compose.yml`. Each setting has one job:

| Setting | What it does | Why it matters |
|---|---|---|
| `networks: red_net / blue_net / llm_net` with `internal: true` | One private network per tenant, with no route to the internet or host | Tenants cannot talk to each other or call out; the only bridge is the gateway |
| `cap_drop: [ALL]` | Removes all special Linux privileges (raw sockets, mounting, changing ownership, ...) | Even if code runs as root, it has almost no powers |
| `read_only: true` | The container's filesystem cannot be written | Malware cannot drop files or change binaries |
| `tmpfs: [/tmp]` | A small in-memory writable `/tmp` | Programs that need scratch space still work, and it vanishes on stop |
| `user: "10001:10001"` | Runs as an unprivileged user, not root | A compromised process cannot act as root |
| `pids_limit: 128` | Max 128 processes | Stops fork bombs |
| `mem_limit: 512m`, `cpus: 0.5` | Memory and CPU caps | One tenant cannot starve the others |
| `no-new-privileges:true` | Processes cannot gain privileges (e.g. via setuid binaries) | Blocks privilege escalation |
| seccomp (Docker default) | Blocks dangerous system calls | Reduces kernel attack surface; we deliberately keep the default so tenants don't break |
| `volumes: red_data:/data` | Each tenant gets its own private writable volume | Writable storage without touching the system |
| gateway on `red_net, blue_net, llm_net, mgmt` | The only service attached to every tenant network | The single, observable path between tenants |
| gateway `ports: 127.0.0.1:8080:8080` | Published on localhost only | Reachable from your machine, not from the network |

---

## 11. Component reference

### Tenants (`tenants/`)

One image (`Dockerfile`) is used for all three tenants; the `TENANT_NAME` environment variable selects the role. At start-up, `entrypoint.sh` launches the decoy process, and `tenant.py` plants decoys.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness check |
| `GET /work` | Does real work (appends to `/data/work.log`), proving the tenant functions |
| `GET /call/<target>/<path>` | Calls another tenant **through the gateway** |
| `POST /v1/chat` *(llm only)* | Stub LLM reply |
| `POST /demo/arm` *(llm only)* | Demo helper: makes the next reply echo given text (simulates a leaky model) |

Decoys planted in each tenant:
- `/data/.env` containing `API_KEY=CNRY-<tenant>-<32 hex chars>` (credential canary)
- `/data/.rt_findings.json` in **red** only (file canary)
- a process named `rt_sync_daemon` (process canary)

### Gateway (`gateway/gateway.py`)

- Routes `/<tenant>/<path>` to `http://<tenant>:8000/<path>`.
- **Actor identification:** looks at the connection's **source IP** and matches it to a tenant using Docker's internal DNS. A tenant that sends a fake `X-Tenant` header is not believed; the lie is logged as `spoof_claimed`. A request from the host (outside any tenant network) is `actor: host`.
- Scans every response for `CNRY-(red|blue|llm)-<32 hex>` tokens and records which tenants' tokens it saw.
- Writes one JSON line per request, and (once the collector exists) forwards it to `COLLECTOR_URL`.

Example log line:

```json
{"type":"gateway_request","actor":"blue","target":"llm","path":"/llm/v1/chat","status":200,"tokens_seen":["red"],"ts":1792414502.56}
```

---

## 12. Design: canaries, severity, hash chain

> These parts are owned by Harshit (canaries) and Aditya (classifier, collector, chain). They are specified here so everyone builds to the same contract.

### Canary types

| Canary | Planted as | Fires when |
|---|---|---|
| Credential | `CNRY-<tenant>-<32hex>` in env and `.env` | Tenant A's token appears in a stream attributed to tenant B (log or LLM response). Unique tokens mean ~zero false positives |
| File | `.rt_findings.json` in red's volume | The file is opened or read by something other than red (inotify on the host path) |
| Network | TCP listener on port 9999 per tenant network | Anything connects to it. With correct isolation it never fires |
| Process | Decoy process named `rt_sync_daemon` | Visible from another tenant, meaning a PID namespace is shared |

### Event format (every agent emits this)

```json
{"tenant_victim":"red","tenant_actor":"blue","canary_type":"credential","evidence":"token found in blue stdout"}
```

### Severity (reproducible by hand)

```
severity = boundary_criticality x type_weight x reproducibility

boundary_criticality:  anything -> llm = 1.0 | red <-> blue = 0.9 | other = 0.6
type_weight:           credential = 1.0, file = 0.8, network = 0.7, process = 0.6
reproducibility:       first trip = 0.8, repeated within 60 s = 1.0
```

Example: red↔blue file canary, repeated: 0.9 × 0.8 × 1.0 = **0.72**.

### MITRE ATLAS mapping

Each canary type maps to an ATLAS tactic/technique. **Technique IDs must be looked up on https://atlas.mitre.org and copied exactly. Do not type IDs from memory**, because ATLAS changes between versions.

### Hash chain (tamper evidence)

Each log entry stores the hash of the previous entry: `entry_hash = SHA-256(canonical_json(entry) + prev_hash)`, starting from a fixed `GENESIS` value. Rules: one writer with a lock (so entries cannot fork the chain), canonical JSON (`sort_keys=True`, fixed separators), and the log stored only inside the collector container.

Honest weakness: a plain chain detects an edit in the middle, but not deletion of the last entries or a full recompute. Mitigation: the dashboard shows the current **head hash**, which is periodically saved externally (git commit or screenshot), and entries may be HMAC-signed with a key kept outside the collector's volume.

---

## 13. Command cheat sheet

| Goal | Command |
|---|---|
| Start everything | `docker compose up -d --build` |
| Status | `docker compose ps` |
| Run all isolation tests | `./tests/isolation_check.sh` |
| Gateway log (live) | `docker compose logs -f gateway` |
| Gateway log (last lines) | `docker compose logs gateway \| tail -5` |
| Shell inside a tenant | `docker compose exec red bash` |
| Run credential-leak scenario | `./demo/breakit.sh leak` |
| Break network isolation | `./demo/breakit.sh net` |
| Restore network isolation | `./demo/breakit.sh net-undo` |
| Normal traffic for N seconds | `./demo/normal_traffic.sh 120` |
| Stop | `docker compose down` |
| Full reset | `docker compose down -v` |
| Rebuild only the gateway | `docker compose up -d --build gateway` |

---

## 14. Troubleshooting

**`docker: command not found` in Ubuntu (Windows)**
Docker Desktop's WSL integration is off. Docker Desktop → Settings → Resources → WSL Integration → enable **Ubuntu** → Apply & Restart.

**`Cannot connect to the Docker daemon`**
Docker Desktop is not running (Windows), or the service is stopped (Linux: `sudo systemctl start docker`).

**`permission denied while trying to connect to the Docker daemon socket` (Linux)**
```bash
sudo usermod -aG docker $USER && newgrp docker
```

**`docker compose` not found but `docker-compose` is** (older Linux installs)
Use `docker-compose` everywhere, and run:
```bash
sed -i 's/docker compose/docker-compose/g' tests/isolation_check.sh demo/*.sh
```

**Container restarts or exits with `exec format error` / `bad interpreter` / `^M`**
Windows line endings (CRLF) got into the scripts. Fix inside Ubuntu:
```bash
sed -i 's/\r$//' tenants/entrypoint.sh tests/*.sh demo/*.sh
docker compose up -d --build
```
Prevent it by cloning inside WSL (Step 4); `.gitattributes` also forces LF.

**`bash: ./tests/isolation_check.sh: Permission denied`**
```bash
chmod +x tests/isolation_check.sh demo/*.sh tenants/entrypoint.sh
```

**Port 8080 already in use**
Another program uses it. Find it with `sudo ss -ltnp | grep 8080`, stop it, or change `"127.0.0.1:8080:8080"` in `docker-compose.yml` (and use the new port in the `curl` commands and in `demo/breakit.sh`).

**First build is very slow or fails to download**
The image download needs internet (once). Check your connection or VPN/proxy, then rerun `docker compose up -d --build`.

**WSL: `WslRegistrationDisabled` / virtualization errors**
Enable virtualization (Intel VT-x or AMD SVM) in BIOS/UEFI. In Windows Features, make sure **Virtual Machine Platform** and **Windows Subsystem for Linux** are on.

**`breakit.sh net-undo` prints an error**
Blue was not attached to red's network (already undone). Harmless.

**Tests fail right after `up`**
Wait about 15 seconds for the health checks, then rerun `./tests/isolation_check.sh`.

**Something is stuck or weird**
Full reset: `docker compose down -v && docker compose up -d --build`.

---

## 15. Known limitations (honest list)

- **Containers share the host kernel.** A kernel exploit could escape them. Stronger isolation would use gVisor or Kata Containers (future work).
- **Docker's default seccomp profile** is used, not a custom one. A custom profile risks breaking tenants and objective 01.
- The gateway is a simple proxy: it detects known CNRY tokens, not arbitrary secrets or encoded leaks.
- The **process canary** is the weakest signal (only fires on shared PID namespaces).
- The **file canary** cannot say *who* opened the file via inotify alone (it infers from which containers mount the volume). `fanotify` would give a PID.
- A plain **hash chain** cannot detect truncation or a full recompute without an external head-hash anchor or HMAC (see Section 12).
- Stub LLM only: no real model is used.

---

## 16. Team

| Person | Area |
|---|---|
| **Ayush** | Isolation baseline, gateway, stub LLM, break-it scenarios, integration |
| **Harshit** | Canary agents (credential, file, network, process) |
| **Aditya** | Classifier, severity scoring, hash chain, collector API, dashboard |

Contributing: create a branch, make your change, run `./tests/isolation_check.sh` (must stay at all-pass), and open a pull request.
