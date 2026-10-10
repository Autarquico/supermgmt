MODULE  := github.com/autarquico/supermgmt
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

GOVULNCHECK_VERSION := v1.8.0
CROSS_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
NOT_YET := @echo "not available until M2 (spec §31)"

# Go refuses to test or lint a tree without packages; skip until the first one lands.
HAS_GO := $(shell find . -name '*.go' -not -path './.git/*' -print -quit)
IF_GO := @[ -z "$(HAS_GO)" ] && echo "no Go packages yet; skipping" ||

.DEFAULT_GOAL := help
.PHONY: help build test test-race lint vuln generate integration cross-build \
	api-check e2e snapshot release-check

help: ## List targets
	@grep -hE '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Build dist/sm
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sm ./cmd/sm

test: ## Run unit tests
	$(IF_GO) go test -count=1 -shuffle=on ./...

test-race: ## Run unit tests with the race detector
	$(IF_GO) go test -race -count=1 -shuffle=on ./...

lint: ## Run golangci-lint and the formatter check
	$(IF_GO) { golangci-lint run ./... && golangci-lint fmt --diff; }

vuln: ## Run govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

generate: ## Regenerate files and fail on drift
	go generate ./...
	@test -z "$$(git status --porcelain)" || { git status --porcelain; echo 'generated files drifted'; exit 1; }

integration: ## Run integration tests
	go test -tags=integration ./test/integration/...

cross-build: ## Compile for linux/darwin x amd64/arm64 with CGO disabled
	@set -e; for target in $(CROSS_TARGETS); do \
		echo "build $$target"; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go build -trimpath -o /dev/null ./...; \
	done

api-check: ## Not available until M2
	$(NOT_YET)

e2e: ## Not available until M2
	$(NOT_YET)

snapshot: ## Not available until M2
	$(NOT_YET)

release-check: ## Not available until M2
	$(NOT_YET)
