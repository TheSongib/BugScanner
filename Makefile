.PHONY: build build-orchestrator build-worker up down logs test clean migrate

# Build both binaries
build: build-orchestrator build-worker

build-orchestrator:
	go build -o bin/orchestrator ./cmd/orchestrator

build-worker:
	go build -o bin/worker ./cmd/worker

# Docker Compose commands
up:
	docker compose -f deployments/docker-compose.yml up -d --build

up-infra:
	docker compose -f deployments/docker-compose.yml up -d postgres redis rabbitmq

down:
	docker compose -f deployments/docker-compose.yml down

logs:
	docker compose -f deployments/docker-compose.yml logs -f

logs-worker:
	docker compose -f deployments/docker-compose.yml logs -f worker

logs-orchestrator:
	docker compose -f deployments/docker-compose.yml logs -f orchestrator

# Save the last 500 lines of worker logs to a file for debugging.
# Run this after a scan completes so Claude can read the logs.
LOGFILE ?= /tmp/bugscanner-worker.log
save-worker-logs:
	docker compose -f deployments/docker-compose.yml logs --no-log-prefix --tail=500 worker > $(LOGFILE) 2>&1
	@echo "Worker logs saved to $(LOGFILE)"

# Scale workers
scale-workers:
	docker compose -f deployments/docker-compose.yml up -d --scale worker=$(WORKERS)

# Run tests
test:
	go test ./... -v

test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

# Database
migrate:
	@echo "Migrations run automatically on orchestrator startup"

# Development: run locally (requires infra running via up-infra)
dev-orchestrator: build-orchestrator
	DATABASE_URL=postgres://scanner:changeme@localhost:5432/bugscanner?sslmode=disable \
	RABBITMQ_URL=amqp://scanner:changeme@localhost:5672/ \
	REDIS_URL=redis://localhost:6379/0 \
	DATABASE_MIGRATIONS_PATH=./migrations \
	./bin/orchestrator

dev-worker: build-worker
	DATABASE_URL=postgres://scanner:changeme@localhost:5432/bugscanner?sslmode=disable \
	RABBITMQ_URL=amqp://scanner:changeme@localhost:5672/ \
	REDIS_URL=redis://localhost:6379/0 \
	./bin/worker

# Lint
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out

# Tidy dependencies
tidy:
	go mod tidy

# Quick start: bring up infra + build + run
quickstart: up-infra build
	@echo ""
	@echo "Infrastructure is running. Start the services:"
	@echo "  Terminal 1: make dev-orchestrator"
	@echo "  Terminal 2: make dev-worker"
	@echo ""
	@echo "Then create a scan:"
	@echo '  curl -X POST http://localhost:8080/api/v1/scans -H "Content-Type: application/json" -d '"'"'{"target": "example.com"}'"'"''
