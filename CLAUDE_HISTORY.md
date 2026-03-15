# Bug Scanner — Claude Session History

## Project Overview
A distributed bug bounty scanner built in Go. Chains ProjectDiscovery tools through a 5-stage pipeline via RabbitMQ. Results stored in PostgreSQL. Discord/Slack webhook notifications on findings.

**Working directory:** `/Users/brandon/Documents/VSCode/Bug Scanner/`

---

## Tech Stack
- **Language:** Go 1.24 (`go.mod`: `go 1.24.0`, `Dockerfile.worker`: `golang:1.24-alpine`)
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
  queue.discovery  → subfinder + shuffledns+massdns (amass not installed, logs WARN and continues)
       │
  queue.portscan   → naabu (-s connect TCP scan, no NET_RAW needed)
       │
  queue.httpprobe  → httpx
       │
  queue.crawl      → katana + form extraction
       │
  queue.vulnscan   → nuclei (4-pass: exposures+misconfig+panels / DAST GET / DAST POST forms / CVE critical+high)
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
FROM projectdiscovery/subfinder:latest  AS subfinder
FROM projectdiscovery/shuffledns:latest AS shuffledns   # massdns is at /usr/bin/massdns in this image
FROM projectdiscovery/naabu:latest      AS naabu
FROM projectdiscovery/httpx:latest      AS httpx
FROM projectdiscovery/katana:latest     AS katana
FROM projectdiscovery/nuclei:latest     AS nuclei
# Copies into alpine:3.19 runtime:
#   /usr/local/bin/subfinder, /usr/local/bin/shuffledns, /usr/local/bin/massdns
#   /usr/local/bin/naabu, /usr/local/bin/httpx, /usr/local/bin/katana, /usr/local/bin/nuclei
# RUN nuclei -update-templates  (bakes templates into image at /root/nuclei-templates/)
# RUN wget wordlists to /usr/share/wordlists/dns.txt and /usr/share/wordlists/resolvers.txt
# COPY nuclei-templates/custom/ /root/custom-templates/
```
- **shuffledns** binary is at `/usr/bin/shuffledns` (not `/usr/local/bin/`) in the PD image.
- **massdns** binary (shuffledns backend) is at `/usr/bin/massdns` in the PD shuffledns image. MUST be copied separately — without it, shuffledns exits with "could not find massdns binary".
- Nuclei templates baked into image at `/root/nuclei-templates/` (not `/root/.local/nuclei-templates/`).
- Docker volume `nuclei-templates` mounted at `/root/nuclei-templates` for live template refresh without rebuilding.
- Custom templates at `/root/custom-templates/` (copied from `nuclei-templates/custom/` at build time).
- **amass**: OWASP took it over; ghcr.io image requires auth (403). Not in image. Discovery logs WARN and continues with subfinder + shuffledns.
- RabbitMQ consumer timeout set to 2 hours (`RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS: "-rabbit consumer_timeout 7200000"`) because 4-pass nuclei scan can run up to 53 minutes worst case.

---

## Current Status (Session 6 — PRODUCTION READY ✓)

### Pipeline is fully working end-to-end ✓
Confirmed working scan against `scanme.nmap.org` (scan `0d4c9f5b`):
- Discovery: subfinder + shuffledns (now fixed — massdns added to image); amass logs WARN gracefully
- Portscan: naabu TCP connect scan finds port 80 in ~5s
- HTTPProbe: httpx finds `live_services:1` (Apache 2.4.7 / Ubuntu)
- Crawl: katana discovers **779 URLs**
- VulnScan: Pass 1 (3.5 min), Pass 2 DAST, Pass 4 CVE — 2 findings stored
- Total scan time: **~6 minutes** for a single-hostname target

### Recommended quick test target
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org"}'
```
`scanme.nmap.org` is Nmap's official sandbox (explicitly permitted). ~6 min scan. Typical findings: `apache-mod-negotiation-listing` (low), `http-missing-security-headers` (info). Good for verifying the pipeline runs without errors.

### Recommended vuln-focused test target
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "testphp.vulnweb.com", "scope_in": ["^([a-z0-9-]+\\.)?vulnweb\\.com$"]}'
```
Acunetix's deliberately vulnerable PHP site. Expect ~35-40 min. As of Session 5: 43 findings (19 critical SQLi + 24 medium XSS including POST form vulns). Note: server is occasionally unreachable (AWS); retry if portscan returns 0 ports.

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

### Nuclei four-pass design (Session 4+5+6)
VulnScan now runs four nuclei passes per job:
1. **Pass 1** — `-t http/exposures/ -t http/misconfiguration/ -t http/exposed-panels/` (8 min timeout): backup files, phpinfo, git exposure, misconfigs, exposed admin panels (Grafana, Jenkins, Kubernetes, etc.).
2. **Pass 2** — `-dast -t /root/custom-templates/` (15 min timeout): fuzzes GET params for SQLi, XSS, LFI, open redirect bypass, broken access control. Loads custom templates alongside built-in DAST.
3. **Pass 3** — `-dast -im jsonl` (10 min timeout): fuzzes POST form body params. Only runs if `FormTargets` is non-empty in the payload (katana form extraction must find forms).
4. **Pass 4** — `-t http/cves/ -severity critical,high` (20 min timeout): ~1500 CVE templates for known exploitable vulns (RCE, auth bypass, SSRF, SQLi CVEs). Independent of commonArgs so `-severity` can be overridden.

Max worst-case: 8+15+10+20 = 53 minutes. RabbitMQ consumer timeout set to 2 hours to accommodate this.

Previously ran ALL 9000+ `http/` templates with a 30-min timeout — always killed with 0 output.

### testphp.vulnweb.com server intermittency
The Acunetix test server at 44.228.249.3 (AWS) is sometimes unreachable (no port 80 response). This is an external issue, not a code issue. Scans that hit a down window will terminate at portscan (0 ports found). Retry the scan when the server is up.

### shuffledns requires massdns
shuffledns is a wrapper around massdns (DNS resolver backend). Both binaries must be in the worker image. `massdns` lives at `/usr/bin/massdns` in the `projectdiscovery/shuffledns` image. Copied alongside shuffledns in Dockerfile.worker. Without it, shuffledns exits with FTL "could not find massdns binary" and discovery falls back to subfinder only.

### amass not installed
OWASP took over amass; `ghcr.io/owasp-amass/amass:latest` requires authentication (403 on anonymous pull). Not in the image. Discovery stage logs WARN and continues. subfinder + shuffledns provides equivalent coverage.

### naabu requires TCP connect scan in Docker
`-s connect` flag is required. Default SYN scan needs `NET_RAW` capability (raw sockets), which Docker containers don't have without `--cap-add NET_RAW`. Without `-s connect`, naabu silently returns 0 results.

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

### Session 4 (2026-03-10)
23. **nuclei `-dast` replaces template set** — `-dast` flag does NOT add to existing templates, it replaces them with only 54 DAST templates. Previously combined with `-t` causing no output. Fixed with two-pass approach: Pass 1 = passive templates, Pass 2 = `-dast` only.
24. **pgx v5 NULL column scan** — pgx v5 cannot scan SQL NULL into a non-pointer `string`. Fixed by using `*string` temp vars for all nullable columns in `vulnerability.go` and `scan.go` (`subdomainID`, `templateName`, `matchedAt`, `curlCommand`, `notes`, `workerID`, `errorMessage`).
25. **nuclei passive pass timeout** — Running all 9000+ `http/` templates always exceeded the 20-min timeout with 0 output. Confirmed two-pass DAST scan finding 36 vulnerabilities (16 critical SQLi + 20 medium XSS) on testphp.vulnweb.com.

### Session 6 (2026-03-15)
30. **massdns missing from worker image** — shuffledns requires massdns as its DNS resolver backend. Binary is at `/usr/bin/massdns` in the `projectdiscovery/shuffledns` image. Added `COPY --from=shuffledns /usr/bin/massdns /usr/local/bin/massdns` to Dockerfile.worker. Previously shuffledns exited with FTL "could not find massdns binary" on every run.
31. **naabu SYN scan silently returning 0 ports** — Default SYN scan requires `NET_RAW` capability (raw sockets). Docker containers don't have this by default. Fixed by adding `-s connect` to naabu args to use TCP connect scan, which works without elevated privileges.
32. **Nuclei scanner buffer truncating large outputs** — `bufio.Scanner` default 64KB buffer, previously set to 1MB, was silently dropping findings when output exceeded the cap. Increased to 10MB in `parser/nuclei.go`.
33. **API returning `null` instead of `[]`** — pgx returns nil Go slices when no rows found. `json.Marshal(nil slice)` = `null`. Added nil-slice guards in `handlers.go` before all list responses (`scans`, `jobs`, `vulns`).
34. **Nuclei volume at wrong path** — docker-compose.yml mounted `nuclei-templates` volume at `/root/.local/nuclei-templates` but nuclei stores templates at `/root/nuclei-templates/`. Volume was unused. Fixed to correct path.
35. **RabbitMQ consumer timeout too short** — Default 30-minute timeout causes RabbitMQ to forcibly close the consumer channel mid-scan. Extended to 2 hours (7200000ms) via `RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS`.
36. **Added Pass 4 (CVE scan)** — New nuclei pass using `http/cves/` templates filtered to `critical,high` severity with 20-minute timeout. Runs ~1500 CVE templates for known exploitable vulnerabilities.
37. **Added exposed-panels to Pass 1** — `http/exposed-panels/` directory added to passive pass. Covers Kubernetes dashboard, Grafana, Jenkins, ingress-nginx, etc.
38. **Custom Nuclei templates created** (in `nuclei-templates/custom/`):
    - `open-redirect-path-traversal-bypass.yaml` — Fuzzes 27 redirect param names with `/..//` path traversal bypass payloads. Uses interactsh OOB + Location header regex. (HackerOne #3599248)
    - `cross-domain-redirect.yaml` — Detects absolute cross-domain redirects via DSL: `!contains(tolower(header), tolower(Hostname))`. Severity: info. (HackerOne #3595764)
    - `broken-access-control-privilege-params.yaml` — Fuzzes 26 privilege-related POST body fields with 23 escalation values. Requires reflected value in response to reduce FPs. Severity: medium.

### Session 5 (2026-03-11)
26. **Nuclei passive pass scoped** — Changed Pass 1 from `-t /root/nuclei-templates/http/` (9000+ templates, always times out) to `-t http/exposures/ -t http/misconfiguration/` (~200 templates). Timeout reduced from 20 min to 8 min. Now reliably completes on single-URL httpprobe jobs.
27. **POST form fuzzing added** — `katana -form-extraction` does not emit POST form entries in non-headless mode (confirmed by inspection — only GET link entries appear). Headless Chromium is in the worker image but hangs in Docker. Solution: new `formextract.go` file uses `golang.org/x/net/html` to GET each crawled page, parse `<form>` elements, extract field names, and build synthetic katana-format JSONL. These are passed to a new Pass 3 (`-dast -im jsonl`) which fuzzes POST body params. Caught 3 new findings: `userinfo.php` SQLi, `userinfo.php` XSS, `guestbook.php` XSS.
28. **Go version bump** — Adding `golang.org/x/net` as a direct dep caused `go mod tidy` to upgrade the `go` directive to 1.25+ (matching local toolchain 1.26.1). Resolved by pinning `x/net@v0.19.0`, `x/sync@v0.6.0`, and other `x/*` to older versions compatible with go 1.24. Updated `Dockerfile.worker` from `golang:1.22-alpine` → `golang:1.24-alpine`.
29. **VulnScanPayload extended** — Added `FormTargets []string` field to carry raw katana-format JSONL lines from crawl stage through the message queue to the vulnscan stage. Crawl stage calls `extractFormsFromPages()` → `parseFormsFromURLs()` after katana completes.

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
