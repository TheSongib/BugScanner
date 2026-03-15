# Bug Bounty Scanner

A distributed, automated reconnaissance and vulnerability scanning platform for bug bounty hunting. Built in Go with a pipeline architecture that chains together the industry-standard ProjectDiscovery tool suite.

## How It Works

When you submit a target domain, the system runs a 5-stage pipeline automatically:

```
Target Domain
     │
     ▼
[1] Asset Discovery      subfinder + shuffledns → finds all subdomains
     │
     ▼
[2] Port Scanning        naabu → finds open ports on live hosts
     │
     ▼
[3] HTTP Probing         httpx → identifies live web services + tech stack
     │
     ▼
[4] Crawling             katana → maps endpoints, JS files, API routes
     │
     ▼
[5] Vulnerability Scan   nuclei — 4-pass scan (see below)
     │
     ▼
Results stored in PostgreSQL + Discord/Slack alert on findings
```

### Vulnerability Scan — 4-Pass Nuclei

| Pass | Mode | Templates | What It Finds |
|---|---|---|---|
| 1 | Standard | ~9,000 nuclei http/ templates | CVEs, misconfigs, exposed panels, default credentials, subdomain takeover, headers, SSRF, CORS, XXE, SSTI, JWT issues |
| 2 | DAST fuzzing | nuclei built-in DAST (54 templates) | SQLi, XSS, LFI, open redirect — actively fuzzes all discovered parameters |
| 3 | Standard | 15 custom detection templates | GraphQL introspection/CSRF, host header injection, password reset poisoning, CRLF injection, cache poisoning, cache deception, CORS bypass, OAuth redirect_uri bypass, Sentry DSN exposure, prompt injection |
| 4 | DAST fuzzing | 5 custom fuzzing templates | Blind XSS (OOB), NoSQL injection, SSRF via webhook params (OOB), prototype pollution |

Everything runs concurrently across distributed workers. You can scale to 50 workers in parallel to cover large scopes in minutes.

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) — must be installed and **running**
- That's it. Everything else runs inside Docker.

---

## Quick Start (New Computer Setup)

### 1. Clone / copy the project

```bash
cd /path/to/Bug\ Scanner
```

### 2. Configure notifications (optional but recommended)

Copy the example env file:

```bash
cp deployments/.env.example deployments/.env
```

Edit `deployments/.env` and add your webhook URLs:

```env
POSTGRES_PASSWORD=changeme
RABBITMQ_PASSWORD=changeme
WORKER_CONCURRENCY=3
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR_WEBHOOK_HERE
```

To get a Discord webhook: Server Settings → Integrations → Webhooks → New Webhook → Copy URL

### 3. Start everything

```bash
make up
```

This builds and starts all 5 containers:
- **PostgreSQL** — stores all scan data
- **Redis** — enforces rate limits
- **RabbitMQ** — job queue between orchestrator and workers
- **Orchestrator** — HTTP API server on port 8080
- **Worker** (×2) — runs the scanning tools

**First build takes 3–5 minutes** (downloading tool images). Subsequent starts are instant.

### 4. Verify everything is running

```bash
make logs
```

You should see the orchestrator and both workers connect successfully. Or check container status:

```bash
docker compose -f deployments/docker-compose.yml ps
```

All containers should show `healthy` or `running`.

### 5. Test the API

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### 6. Import the Postman collection (optional)

A ready-to-use Postman collection is included at `execution scripts/Basic Runs.postman_collection.json`.

Import it into Postman (**File → Import**) and you get:
- **Create Scan** — fires a scan and automatically saves the returned `scan_id` as a collection variable
- **Scan Status** — checks progress using `{{scan_id}}`
- **Get Results** — fetches vulnerability findings using `{{scan_id}}`
- **List All Runs** — lists all scans
- **Cancel Run** — cancels the current `{{scan_id}}`

Run **Create Scan** first — every subsequent request will automatically target that scan.

---

## Usage

### Start a Scan

Submit a target domain. The scan kicks off immediately and runs the full 5-stage pipeline in the background.

**Basic scan (auto-generates scope for all subdomains):**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "hackerone.com"}'
```

**Scan with explicit scope (recommended for bug bounties):**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "hackerone.com",
    "scope_in": [
      ".*\\.hackerone\\.com$",
      ".*\\.hackerone-ext-content\\.com$"
    ],
    "scope_out": [
      "^www\\.hackerone\\.com$",
      ".*\\.vpn\\.hackerone\\.com$"
    ]
  }'
```

`scope_in` — regex patterns that assets **must** match to be scanned
`scope_out` — regex patterns that assets matching these are **excluded** (never scanned)

Response:
```json
{
  "scan": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "running",
    "target": "hackerone.com",
    "created_at": "2026-03-08T00:30:00Z"
  }
}
```

Save the `id` — you'll use it to check results.

---

### Check Scan Status & Progress

```bash
curl http://localhost:8080/api/v1/scans/550e8400-e29b-41d4-a716-446655440000 | jq .
```

Response shows the scan plus each pipeline stage's job status:
```json
{
  "scan": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "running",
    "target": "hackerone.com"
  },
  "jobs": [
    { "stage": "discovery",  "status": "completed", "output_count": 142 },
    { "stage": "portscan",   "status": "completed", "output_count": 89  },
    { "stage": "httpprobe",  "status": "running",   "output_count": 0   },
    { "stage": "crawl",      "status": "pending",   "output_count": 0   },
    { "stage": "vulnscan",   "status": "pending",   "output_count": 0   }
  ]
}
```

Scan `status` values: `pending` → `running` → `completed` / `failed` / `cancelled`

---

### Get Vulnerability Results

```bash
curl http://localhost:8080/api/v1/scans/550e8400-e29b-41d4-a716-446655440000/results | jq .
```

Results are sorted by severity (critical first):
```json
{
  "scan": { "id": "...", "status": "completed" },
  "vulnerabilities": [
    {
      "id": "abc123",
      "template_id": "CVE-2021-44228",
      "template_name": "Apache Log4j RCE",
      "severity": "critical",
      "matched_url": "https://api.hackerone.com/v1/login",
      "curl_command": "curl -X POST ...",
      "created_at": "2026-03-08T01:15:00Z"
    },
    {
      "template_id": "exposed-git-config",
      "severity": "medium",
      "matched_url": "https://assets.hackerone.com/.git/config"
    }
  ]
}
```

---

### List All Scans

```bash
curl "http://localhost:8080/api/v1/scans?limit=20&offset=0" | jq .
```

---

### List Vulnerabilities by Severity

```bash
# All critical findings across all scans
curl "http://localhost:8080/api/v1/vulnerabilities?severity=critical" | jq .

# All findings for a specific scan
curl "http://localhost:8080/api/v1/vulnerabilities?scan_id=550e8400-e29b-41d4-a716-446655440000" | jq .
```

Severity levels: `info`, `low`, `medium`, `high`, `critical`

---

### Cancel a Running Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans/550e8400-e29b-41d4-a716-446655440000/cancel
```

---

### Mark a Finding as False Positive

```bash
curl -X POST http://localhost:8080/api/v1/vulnerabilities/abc123/false-positive \
  -H "Content-Type: application/json" \
  -d '{"notes": "WAF blocks this, not exploitable"}'
```

---

### Mark a Finding as Triaged (Reported)

```bash
curl -X POST http://localhost:8080/api/v1/vulnerabilities/abc123/triage \
  -H "Content-Type: application/json" \
  -d '{"notes": "Reported to HackerOne - report #123456"}'
```

---

## Scaling Workers

The more workers running, the faster scans complete on large scopes. Scale up:

```bash
# Run 5 workers in parallel
make scale-workers WORKERS=5

# Run 10 workers for a massive scope
make scale-workers WORKERS=10
```

Scale back down when done to save resources:

```bash
make scale-workers WORKERS=1
```

---

## Viewing Live Logs

```bash
make logs                # all containers
make logs-worker         # worker output (tool execution, findings)
make logs-orchestrator   # API server logs (requests, errors)
```

Worker logs show each tool execution in real time:
```
{"level":"INFO","msg":"executing tool","tool":"subfinder","args":["-d","hackerone.com"]}
{"level":"INFO","msg":"tool completed","tool":"subfinder","duration":"8.2s","stdout_len":4821}
{"level":"INFO","msg":"discovery complete","domain":"hackerone.com","subdomains_found":142}
{"level":"INFO","msg":"vulnerability found","template":"exposed-git-config","severity":"medium","url":"https://..."}
```

---

## RabbitMQ Management UI

You can visually inspect the job queues in your browser:

```
http://localhost:15672
Username: scanner
Password: changeme
```

Shows queue depths, message rates, and consumer counts for each pipeline stage.

---

## Stopping & Restarting

```bash
# Stop everything (data is preserved in Docker volumes)
make down

# Start again (instant, no rebuild)
make up

# Stop and delete ALL data (wipe the database)
docker compose -f deployments/docker-compose.yml down -v
```

---

## Notifications Setup

When a medium/high/critical vulnerability is found, the system fires a webhook immediately.

**Discord:** Create a webhook in your server under Server Settings → Integrations → Webhooks. Set `DISCORD_WEBHOOK_URL` in `deployments/.env`.

**Slack:** Create an incoming webhook app at api.slack.com. Set `SLACK_WEBHOOK_URL` in `deployments/.env`.

**Minimum severity to notify** (default: `medium`):
Edit `configs/config.yaml`:
```yaml
notify:
  min_severity: "high"   # only ping for high and critical
```

Restart workers after changing config: `make down && make up`

---

## Configuration Reference

All settings live in `configs/config.yaml` and can be overridden with environment variables.

| Setting | Default | Description |
|---|---|---|
| `server.port` | `8080` | API server port |
| `worker.concurrency` | `3` | Jobs per worker container processed simultaneously |
| `rate_limit.per_target` | `30` | Max requests/sec to any single target |
| `rate_limit.per_tool.nuclei` | `50` | Max nuclei requests/sec |
| `rate_limit.per_tool.naabu` | `200` | Max port scan packets/sec |
| `notify.min_severity` | `medium` | Minimum severity to trigger webhook alert |

**Important:** Keep `rate_limit.per_target` reasonable (≤50 rps). Blasting a target with thousands of requests per second is an accidental DoS attack and will get you banned from bug bounty programs.

---

## Custom Nuclei Templates

The scanner ships with 20 custom nuclei templates in `nuclei-templates/custom/`, automatically baked into the worker image at build time. They run in Pass 3 and Pass 4 of the vuln scan.

**Detection templates** (`nuclei-templates/custom/detection/` — Pass 3):

| Template | Detects |
|---|---|
| `graphql-introspection.yaml` | GraphQL `__schema` introspection left enabled |
| `graphql-batch-query.yaml` | GraphQL batch mutations (rate-limit bypass vector) |
| `graphql-csrf-get.yaml` | GraphQL mutations accepted via GET or `text/plain` POST |
| `host-header-injection.yaml` | `X-Forwarded-Host` reflected in response body/headers |
| `password-reset-host-poisoning.yaml` | Password reset uses poisoned Host header (OOB confirmed) |
| `crlf-injection.yaml` | CRLF sequences in URL params inject raw HTTP headers |
| `web-cache-poisoning.yaml` | Unkeyed headers reflected in cacheable responses |
| `web-cache-deception.yaml` | Auth endpoints serve PII when fake `.css`/`.js` suffix appended |
| `cors-origin-bypass.yaml` | Arbitrary/null origin + `Access-Control-Allow-Credentials: true` |
| `oauth-redirect-uri-bypass.yaml` | OAuth `redirect_uri` accepts arbitrary external domain |
| `sentry-dsn-exposure.yaml` | Sentry DSN key in HTML, JS bundles, or config JSON |
| `prompt-injection-endpoint.yaml` | AI/LLM endpoints disclose system prompt after injection |
| `open-redirect-path-traversal-bypass.yaml` | `//`, `/%2f/` redirect bypass (OOB confirmed) |
| `cross-domain-redirect.yaml` | Redirect param accepts arbitrary external URL |
| `broken-access-control-privilege-params.yaml` | `role:admin`/`isAdmin:true` accepted on update endpoints |

**DAST fuzzing templates** (`nuclei-templates/custom/fuzz/` — Pass 4):

| Template | Detects |
|---|---|
| `blind-xss-oob.yaml` | Blind XSS via interactsh OOB in all params + headers |
| `nosql-injection-query.yaml` | MongoDB `$ne`/`$gt`/`$regex` in query strings |
| `nosql-injection-json.yaml` | MongoDB `$ne`/`$gt` in JSON POST bodies |
| `ssrf-webhook-params.yaml` | SSRF via 35+ webhook/URL param names (OOB confirmed) |
| `prototype-pollution.yaml` | `__proto__`/`constructor.prototype` in query strings + JSON |

To add a new template: create the YAML in the appropriate subfolder, then run `make up`. The Dockerfile automatically COPYs both template directories into the image.

---

## Bug Bounty Workflow

1. Find a program on [HackerOne](https://hackerone.com) or [Bugcrowd](https://bugcrowd.com)
2. Read the scope carefully — note which domains are in-scope and out-of-scope
3. Start a scan with explicit `scope_in` and `scope_out` patterns matching the program rules
4. Watch `make logs-worker` for live findings
5. When something interesting surfaces, check the `curl_command` field in the result — it gives you the exact request to reproduce it manually
6. Verify the finding is real (not a false positive) before reporting
7. Mark it triaged with your report number: `POST /vulnerabilities/{id}/triage`

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Your Machine                        │
│                                                         │
│   curl / browser → port 8080                           │
└─────────────────┬───────────────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────────────┐
│              Docker Network                             │
│                                                         │
│  ┌─────────────┐    ┌──────────┐    ┌───────────────┐  │
│  │ Orchestrator│    │ RabbitMQ │    │   PostgreSQL  │  │
│  │  (API :8080)│───▶│ (queues) │    │  (results DB) │  │
│  └─────────────┘    └────┬─────┘    └───────▲───────┘  │
│                          │                  │           │
│                    ┌─────▼──────────────────┤           │
│                    │      Worker ×N         │           │
│                    │                        │           │
│                    │  subfinder → naabu     │           │
│                    │  httpx → katana        │           │
│                    │  nuclei                │           │
│                    └────────────────────────┘           │
│                                                         │
│  ┌──────┐                                               │
│  │ Redis│ (rate limiting)                               │
│  └──────┘                                               │
└─────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

**Containers won't start:**
Make sure Docker Desktop is open and running before any `make` commands.

**Port already in use:**
```bash
make down   # stop existing containers first
make up
```

**Scan stuck in "running" with no progress:**
Check worker logs for errors: `make logs-worker`
The most common cause is a tool failing — the worker logs the exact error.

**`jq` command not found:**
```bash
brew install jq
```

**Want to inspect the database directly:**
```bash
docker exec -it deployments-postgres-1 psql -U scanner -d bugscanner
```
Then run standard SQL: `SELECT * FROM scans;`, `SELECT severity, count(*) FROM vulnerabilities GROUP BY severity;`

**Scan terminates at port scan with 0 ports found:**
The test server (`testphp.vulnweb.com`) or target may be temporarily unreachable. Wait a minute and retry.

**Scan reaches httpx but finds 0 live services:**
This is usually a transient network issue. The port scanner runs web-ports-only to avoid disrupting Docker's connection tracking. Retry the scan.
