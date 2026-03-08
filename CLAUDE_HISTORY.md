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
- **All stages (httpprobe, crawl, vulnscan):** Write targets to **temp files** and pass via `-list <tmpfile>` instead of `/dev/stdin`. httpx had issues reading from piped stdin in Docker containers. httpx also uses `-probe` flag for newer version compatibility.

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
- `internal/runner/runner.go` logs stderr content when a tool produces empty stdout (helps diagnose why a stage found nothing).
- `internal/pipeline/httpprobe.go` logs the full `target_list` it receives.

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

## Current Status / Active Issue (Session 2)

### httpx returning 0 results — STILL UNDER INVESTIGATION
**Symptom:** httpx runs for ~25 seconds on `testphp.vulnweb.com` and produces `stdout_len:0, stderr_len:0`. The pipeline dies at the httpprobe stage.

**What we've tried so far:**
1. ~~Changed target format from `host:port` to `http://host`~~ — did not fix it
2. ~~Switched from stdin pipe to temp file for input~~ — did not fix it (needs testing after rebuild)
3. Added `-probe` flag to httpx args

**What's confirmed working:**
- Discovery stage: finds 0 subdomains but correctly includes the target domain itself (targets:1)
- Portscan stage: naabu finds port 80 open (`stdout_len:270`)
- The temp file + `-probe` changes have been built but need a fresh `make down && make up` to test

**Possible remaining causes:**
- httpx binary from ProjectDiscovery Docker image may have incompatible flags or need different args
- Docker container may have outbound HTTP connectivity issues (naabu uses SYN scanning which is lower-level)
- May need to test by exec'ing into the container: `docker exec -it deployments-worker-1 httpx -u http://testphp.vulnweb.com`

### Recommended test target
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "testphp.vulnweb.com",
    "scope_in": ["^([a-z0-9-]+\\.)?vulnweb\\.com$"]
  }'
```
This is Acunetix's deliberately vulnerable test site with known XSS, SQLi, and misconfigurations.

---

## Known Behaviors / Watch Out For

### Subfinder + example.com = 37,609 subdomains (bad test target)
The auto-generated scope regex `(?i)^.*\.?example\.com$` is too loose. example.com is an IANA documentation domain. Results in ~7 min naabu scan with 0 useful output.

### httpx needs proper URL format
Portscan now formats targets as `http://host` or `https://host` (not bare `host:port`). Non-standard ports get both `http://` and `https://` variants.

### Exit code 2 = no results (not an error)
ProjectDiscovery tools return exit code 2 when they run successfully but find nothing. The runner handles this correctly.

### amass and shuffledns not installed
Not in the Docker image. Discovery stage logs WARN and continues with subfinder only.

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
15. Stdin pipe issues — switched httpx/katana/nuclei to temp file input instead of `/dev/stdin`
16. httpx target format — portscan now formats as `http://host` not `host:port`

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

## File Structure (key files)
```
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
