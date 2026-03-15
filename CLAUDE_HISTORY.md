# Bug Scanner — Claude Session History

## Project Overview
A distributed bug bounty scanner built in Go. Chains ProjectDiscovery tools through a 5-stage pipeline via RabbitMQ. Results stored in PostgreSQL. Discord/Slack webhook notifications on findings.

**Working directory:** `/Users/brandon/Documents/VSCode/Bug Scanner/`

---

## Tech Stack
- **Language:** Go 1.22
- **Module:** `github.com/brandon/bugscanner`
- **API:** chi router, port 8080
- **Database:** PostgreSQL 16 (pgx/v5 driver)
- **Queue:** RabbitMQ 3.13
- **Rate limiting:** Redis 7
- **Deployment:** Docker Compose (`deployments/docker-compose.yml`)

---

## Architecture
```
POST /api/v1/scans
       │
  Orchestrator (HTTP API)
       │ publishes to RabbitMQ
       ▼
  queue.discovery  → subfinder (amass/shuffledns not installed, log WARN and continue)
       │
  queue.portscan   → naabu
       │
  queue.httpprobe  → httpx
       │
  queue.crawl      → katana
       │
  queue.vulnscan   → nuclei (all templates, no -tags filter, 30 min timeout)
       │
  PostgreSQL + Discord/Slack webhook
```

Workers consume all 5 queues simultaneously. Each stage publishes results to the next queue.

### Pipeline stage details
- **Discovery:** Always includes the target domain itself as a scan target (not just subdomains). Marks scan complete if 0 targets found.
- **Portscan:** Formats targets as full URLs for httpx (`http://host` for port 80, `https://host` for 443, both schemes for non-standard ports). Marks scan complete if 0 ports found.
- **HTTPProbe:** Marks scan complete if 0 live services found.
- **HTTPProbe:** Uses `-u <comma-separated-urls>` (inline targets, no temp file, no stdin). Waits 5s before running to let any transient network state from naabu settle. Also uses `-no-fallback-scheme` to avoid double-probing http+https.
- **Crawl/VulnScan:** Write targets to temp files via `os.CreateTemp()` and pass with `-list <tmpfile>`.

### Dead-end handling
Every pipeline stage that could produce 0 results has an else branch that calls `UpdateStatus(completed)` so scans don't hang forever: discovery, portscan, httpprobe.

---

## Logging

### Log file for Claude debugging
```bash
make save-worker-logs   # saves last 500 lines to /tmp/bugscanner-worker.log
make save-worker-logs LOGFILE=~/custom.log  # custom path
```
Claude can read `/tmp/bugscanner-worker.log` to diagnose pipeline issues after a scan completes.

### Timezone
Logs use **US Eastern time** with automatic DST handling (`America/New_York`).
- Implemented via `internal/logging/logger.go` — custom slog handler that converts timestamps.
- Uses `import _ "time/tzdata"` to embed IANA timezone data in the binary (Alpine containers lack tzdata).
- Both `cmd/orchestrator/main.go` and `cmd/worker/main.go` call `logging.Setup()`.

### Diagnostic logging
- `internal/runner/runner.go` logs stderr content whenever it's non-empty (always, not just on empty stdout).
- `internal/pipeline/httpprobe.go` logs full `target_list` and raw httpx stdout (truncated at 2000 chars).
- `internal/pipeline/vulnscan.go` logs raw nuclei stdout (truncated at 2000 chars).

---

## Running the Project

### Prerequisites
- Docker Desktop must be **open and running**
- Go installed (`brew install go`)

### Full Docker Start (recommended)
```bash
make up        # builds everything and starts all containers
make logs      # watch all logs
make logs-worker  # watch worker logs (tool execution output)
make down      # stop everything (data preserved)
```

### Local Dev Mode (faster iteration, no tools)
```bash
make up-infra             # start postgres, redis, rabbitmq only
# Terminal 1:
make dev-orchestrator     # runs API server locally
# Terminal 2:
make dev-worker           # runs worker locally (no tools installed locally)
```

### Environment Variables (set in `deployments/.env`)
```
POSTGRES_PASSWORD=changeme
RABBITMQ_PASSWORD=changeme
WORKER_CONCURRENCY=3
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=
```

---

## Current Dockerfile.worker Strategy
```dockerfile
FROM projectdiscovery/subfinder:latest AS subfinder
FROM projectdiscovery/naabu:latest AS naabu
FROM projectdiscovery/httpx:latest AS httpx
FROM projectdiscovery/katana:latest AS katana
FROM projectdiscovery/nuclei:latest AS nuclei
# Copy /usr/local/bin/<tool> from each image into alpine:3.19 runtime
# Then: RUN nuclei -update-templates (bakes templates into image)
# ENV HOME=/root
```
- Nuclei templates are baked into the image at build time via `RUN nuclei -update-templates`.
- A Docker volume `nuclei-templates` is mounted at `/root/.local/nuclei-templates` for persistence across container restarts.
- Nuclei runs **all templates** (no `-tags` filter) with a 30-minute timeout.

---

## Current Status (Session 3 — RESOLVED)

### Pipeline is fully working end-to-end ✓
Confirmed working scan against `testphp.vulnweb.com` (scan `11d8be92`):
- Discovery: subfinder runs, 0 subdomains, target domain included
- Portscan: naabu finds port 80
- HTTPProbe: httpx finds `live_services:1` (Home of Acunetix Art, PHP 5.6.40)
- Crawl: katana discovers **83 URLs**
- VulnScan: nuclei finds **10 findings** stored in DB (info-severity: nginx-eol, php-eol, idea-folder-exposure, etc.)

### Recommended test target
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "testphp.vulnweb.com",
    "scope_in": ["^([a-z0-9-]+\\.)?vulnweb\\.com$"]
  }'
```
This is Acunetix's deliberately vulnerable test site. Expect ~5 min scan time.

---

## Known Behaviors / Watch Out For

### Subfinder + example.com = 37,609 subdomains (bad test target)
The auto-generated scope regex `(?i)^.*\.?example\.com$` is too loose. example.com is an IANA documentation domain. Results in ~7 min naabu scan with 0 useful output.

### httpx needs proper URL format
Portscan now formats targets as `http://host` or `https://host` (not bare `host:port`). Non-standard ports get both `http://` and `https://` variants.

### Exit code 2 = no results (not an error)
ProjectDiscovery tools return exit code 2 when they run successfully but find nothing. The runner handles this correctly.

### Nuclei/katana use `-jsonl` not `-json`
The ProjectDiscovery tools in the Docker images use `-jsonl` (or `-j`) for JSONL output. Using `-json` prints "flag provided but not defined: -json" to stdout (37 bytes) and exits without scanning.

### naabu port scan scope: web ports only
Naabu is configured to scan only 20 common web ports (`-p "80,443,8080,8443,..."`) at rate 300/s.
- Scanning top-1000 ports at rate 1000/s was filling Docker's conntrack table, blocking all HTTP connections for ~60s after the scan.
- With 20 ports, no conntrack disruption — httpx can connect immediately.

### Setsid: true in runner.go (critical)
`cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}` is set for ALL subprocesses in runner.go.
Without this, tools (especially httpx) run in the parent's process session and exhibit different network behavior than `docker exec`. This was the root cause of httpx producing 0 output for weeks.

### Nuclei 30-min timeout kills crawl-based scans
The vulnscan stage has a 30-minute `RunWithTimeout`. When the crawl stage finds 83 URLs and passes them all to a second nuclei run, nuclei tries to scan 83 URLs × ~7000 templates. At 50 req/s this takes ~3 hours, so the timeout kills it (`exit_code:-1`, 0 stdout — nuclei was killed before flushing output). **Not fixed yet.** Options: increase timeout or reduce template scope for crawled URLs.

The first nuclei run (1 URL from httpprobe) completes fine with findings. So scans still produce results.

### testphp.vulnweb.com server intermittency
The Acunetix test server at 44.228.249.3 (AWS) is sometimes unreachable (no port 80 response). This is an external issue, not a code issue. Scans that hit a down window will terminate at portscan (0 ports found). Retry the scan when the server is up.

### amass and shuffledns not installed
Not in the Docker image. Discovery stage logs WARN and continues with subfinder only.

---

---

## Session 7 (2026-03-15) — H1 Hacktivity Analysis + 20 Custom Nuclei Templates

### Summary
Analyzed ~610 disclosed HackerOne bug bounty reports across 2 batches to identify gaps in the scanner's coverage. Built 20 custom nuclei templates and restructured the vuln scan from 2 passes to 4 passes. Build confirmed working.

### H1 Coverage Analysis
- **Batch 1** (~442 reports — RCE, SSRF, XSS, SQLi, IDOR, path traversal, XXE, SSTI, subdomain takeover, NoSQL, open redirect, HTTP smuggling, deserialization, prompt injection): **~35% coverage**
- **Batch 2** (~168 reports — CSRF, auth bypass, 2FA bypass, business logic, race conditions, clickjacking, GraphQL-specific, OAuth/OIDC, cache poisoning/deception, mobile, file upload chains, DoS, credential exposure): **~13% coverage**
- **Combined: ~29% coverage**
- Batch 2's low rate is structural — business logic, race conditions, 2FA bypass, OAuth flow bugs, and mobile vulnerabilities cannot be reliably automated by a passive/active web scanner

### Pipeline Change: 2-Pass → 4-Pass Nuclei Scan

**Before (2 passes):**
```go
passiveArgs := append([]string{"-t", "/root/nuclei-templates/http/"}, commonArgs...)  // 20 min
dastArgs    := append([]string{"-dast"}, commonArgs...)                               // 15 min
```

**After (4 passes):**
```go
passiveArgs    := append([]string{"-t", "/root/nuclei-templates/http/"}, commonArgs...)          // Pass 1: 20 min
dastArgs       := append([]string{"-dast"}, commonArgs...)                                        // Pass 2: 15 min
customArgs     := append([]string{"-t", "/root/custom-templates/detection/"}, commonArgs...)      // Pass 3: 10 min
customDastArgs := append([]string{"-dast", "-t", "/root/custom-templates/fuzz/"}, commonArgs...) // Pass 4: 12 min
```
Total budget: ~57 min. Well within 2-hour RabbitMQ consumer timeout.

### Dockerfile.worker Change
Added COPY commands to bake custom templates into the worker image:
```dockerfile
COPY nuclei-templates/custom/detection/ /root/custom-templates/detection/
COPY nuclei-templates/custom/fuzz/ /root/custom-templates/fuzz/
```

### 15 Custom Detection Templates (nuclei-templates/custom/detection/)
Run in Pass 3 without -dast. Each probes specific endpoints or injects specific headers:

| Template | What It Catches |
|---|---|
| `open-redirect-path-traversal-bypass.yaml` | //, /%2f/, path traversal redirect bypass + interactsh OOB |
| `cross-domain-redirect.yaml` | Redirect param accepts arbitrary external domain |
| `broken-access-control-privilege-params.yaml` | role:admin / isAdmin:true reflected on update endpoints |
| `graphql-introspection.yaml` | GraphQL __schema introspection enabled in production |
| `graphql-batch-query.yaml` | Batch mutations enabled (rate-limit bypass vector) |
| `graphql-csrf-get.yaml` | GraphQL mutations fire via GET or text/plain POST (CSRF) |
| `host-header-injection.yaml` | X-Forwarded-Host reflected in body/headers |
| `password-reset-host-poisoning.yaml` | Reset endpoint uses poisoned X-Forwarded-Host (interactsh OOB) |
| `crlf-injection.yaml` | CRLF in URL/params injects raw HTTP response headers |
| `web-cache-poisoning.yaml` | Unkeyed headers (X-Forwarded-Host, X-Original-URL) reflected |
| `web-cache-deception.yaml` | Fake .css/.js suffix on auth endpoints returns 200 + PII |
| `cors-origin-bypass.yaml` | Arbitrary + null origin with Access-Control-Allow-Credentials: true |
| `oauth-redirect-uri-bypass.yaml` | OAuth redirect_uri accepts external domain; discovers .well-known |
| `sentry-dsn-exposure.yaml` | Sentry DSN regex in HTML, JS bundles, config JSON |
| `prompt-injection-endpoint.yaml` | AI/LLM endpoints disclosing system prompt after injection |

### 5 Custom DAST Fuzzing Templates (nuclei-templates/custom/fuzz/)
Run in Pass 4 with -dast flag. Use nuclei's fuzzing engine to inject into discovered params:

| Template | What It Catches |
|---|---|
| `blind-xss-oob.yaml` | XSS payloads with interactsh callbacks in query params, body, User-Agent, Referer, X-Forwarded-For |
| `nosql-injection-query.yaml` | $ne/$gt/$regex in query string (MongoDB error-based detection) |
| `nosql-injection-json.yaml` | $ne/$gt in JSON POST body (error + auth bypass detection) |
| `ssrf-webhook-params.yaml` | 35+ webhook/URL param names (url, webhook, callback, dest…) fuzzed with interactsh OOB |
| `prototype-pollution.yaml` | __proto__ and constructor.prototype in query string and JSON body |

### Important: Custom Templates Were Previously Never Called
In prior sessions, custom templates were created in `nuclei-templates/custom/` but:
1. Never referenced in `vulnscan.go`
2. Never COPY'd into the Dockerfile
This was the root cause. Fix was to update both files simultaneously whenever templates are added.

### Verification Checklist (run after any template change)
1. Template YAML files exist in `nuclei-templates/custom/detection/` or `nuclei-templates/custom/fuzz/`
2. `Dockerfile.worker` has `COPY nuclei-templates/custom/detection/ /root/custom-templates/detection/` and `COPY nuclei-templates/custom/fuzz/ /root/custom-templates/fuzz/`
3. `vulnscan.go` Pass 3 uses `-t /root/custom-templates/detection/` and Pass 4 uses `-dast -t /root/custom-templates/fuzz/`
4. All 4 pass results are appended to `allOutput` and passed to `parser.ParseNuclei`
5. `make up` rebuilds and confirms no Docker build errors

---

## Key Bugs Fixed

### Session 1 (2026-03-08)
1. `scope_out` NULL constraint — default to `[]string{}` in `handlers.go`
2. TEXT[] scanning into []string (pgx v5) — use separate vars in `scan.go`
3. `worker_id` NULL scan error — use `*string` pointers in `scan.go`
4. Scans stuck in `running` — added dead-end completion in httpprobe + exit code 2 handling
5. Local dev migrations path — added `DATABASE_MIGRATIONS_PATH` env var
6. Docker worker tool installation — multi-stage Docker build from official PD images
7. Amass not available — removed, subfinder sufficient

### Session 2 (2026-03-08)
8. Scans stuck in `running` (discovery/portscan) — added dead-end completion to discovery and portscan stages
9. Discovery missed leaf hostnames — target domain itself is always included as a scan target
10. Nuclei had no templates — added `RUN nuclei -update-templates` to Dockerfile + volume mount
11. Nuclei tag filtering too restrictive — removed `-tags` flag, runs all templates
12. Nuclei timeout too short — increased from 10 min to 30 min via `RunWithTimeout`
13. DST timezone wrong — added `import _ "time/tzdata"` for Alpine containers
14. Katana relative URLs — crawl stage filters out non-absolute URLs before passing to nuclei
15. Stdin pipe issues — switched httpx to `-u` flag, katana/nuclei to temp file input
16. httpx target format — portscan now formats as `http://host` not `host:port`

### Session 3 (2026-03-09)
17. **httpx 0 output via Go exec** — Root cause: `exec.CommandContext` inherits parent process group/session; subprocesses behave differently from `docker exec`. Fixed by adding `cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}` in `runner.go` to create a new session for every subprocess.
18. **httpx `-probe` flag breaking JSON** — `-probe` flag outputs non-standard JSON with `failed:true` results. Removed.
19. **httpx `-json` → works; `-no-fallback-scheme`** — Added to prevent double-probing http+https (cuts duration 25s→15s).
20. **httpx 0 output after naabu portscan** — naabu's 1000-port connect scan at 1000/s fills Docker conntrack table; recovery takes ~60s. Fixed by scanning only 20 web-relevant ports at 300/s (`-p "80,443,8080,8443,..."`) — no conntrack disruption.
21. **nuclei/katana `-json` flag doesn't exist** — These tool versions use `-jsonl` (not `-json`). "flag provided but not defined: -json" was the 37-byte stdout causing silent failures. Fixed by switching to `-jsonl`.
22. **httpx parser** — Added `input` field as URL fallback, debug logging for skipped results, slog warning on JSON parse failures.

---

## API Quick Reference

```bash
# Create scan
POST http://localhost:8080/api/v1/scans
Body: {"target": "domain.com", "scope_in": ["regex"], "scope_out": ["regex"]}

# List scans
GET http://localhost:8080/api/v1/scans?limit=20&offset=0

# Check scan status + pipeline job progress
GET http://localhost:8080/api/v1/scans/{id}

# Get vulnerability results
GET http://localhost:8080/api/v1/scans/{id}/results

# Cancel scan
POST http://localhost:8080/api/v1/scans/{id}/cancel

# List vulns by severity
GET http://localhost:8080/api/v1/vulnerabilities?severity=critical
GET http://localhost:8080/api/v1/vulnerabilities?scan_id={id}

# Mark false positive
POST http://localhost:8080/api/v1/vulnerabilities/{id}/false-positive
Body: {"notes": "reason"}

# Mark triaged/reported
POST http://localhost:8080/api/v1/vulnerabilities/{id}/triage
Body: {"notes": "HackerOne report #123"}

# Health check
GET http://localhost:8080/health
```

---

## Postman Setup
- Use collection variables: in Tests tab of Create Scan request add:
  `pm.collectionVariables.set("scan_id", pm.response.json().scan.id);`
- Then reference as `{{scan_id}}` in all other request URLs

---

## RabbitMQ Management UI
- URL: `http://localhost:15672`
- User: `scanner` / Pass: `changeme`
- Shows queue depths and consumer counts per pipeline stage

---

## Direct DB Access
```bash
docker exec -it deployments-postgres-1 psql -U scanner -d bugscanner
```
Useful queries:
```sql
SELECT id, status, target, created_at FROM scans ORDER BY created_at DESC;
SELECT severity, count(*) FROM vulnerabilities GROUP BY severity;
SELECT stage, status, output_count FROM scan_jobs WHERE scan_id = 'YOUR-ID';
```

---

## Scale Workers
```bash
make scale-workers WORKERS=5
```

---

## Postman Collection
`execution scripts/Basic Runs.postman_collection.json` — import into Postman via File → Import.
- **Create Scan**: fires a scan and auto-saves `scan_id` to a collection variable via test script
- **Scan Status**: `GET /api/v1/scans/{{scan_id}}`
- **Get Results**: `GET /api/v1/scans/{{scan_id}}/results`
- **List All Runs**: `GET /api/v1/scans`
- **Cancel Run**: `POST /api/v1/scans/{{scan_id}}/cancel`

Run Create Scan first — all other requests use `{{scan_id}}` automatically.

---

## File Structure (key files)
```
execution scripts/           — Postman collection for manual testing (not part of Go source)
cmd/orchestrator/main.go     — API server entry point
cmd/worker/main.go           — Worker entry point
internal/api/handlers.go     — REST endpoint handlers
internal/api/router.go       — Route definitions
internal/logging/logger.go   — Eastern timezone JSON logger
internal/pipeline/           — 5 pipeline stages
internal/parser/             — Tool output parsers (JSON)
internal/repository/         — PostgreSQL CRUD
internal/broker/             — RabbitMQ publish/consume
internal/runner/runner.go    — Tool execution + rate limiting + diagnostic logging
internal/scope/scope.go      — Scope regex enforcement
internal/ratelimit/redis.go  — Redis sliding window limiter
internal/notify/             — Discord + Slack webhooks
migrations/001_initial_schema.up.sql — Full DB schema
deployments/docker-compose.yml
deployments/Dockerfile.worker
deployments/Dockerfile.orchestrator
configs/config.yaml
Makefile
```
