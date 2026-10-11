MODULE  := github.com/autarquico/supermgmt
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

GOVULNCHECK_VERSION := v1.8.0
ACTIONLINT_VERSION := v1.7.7
VACUUM_VERSION := v0.30.6
VACUUM_VERSION := v0.30.6
CROSS_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
NOT_YET := @echo "not available until M2 (spec §31)"

PEER_USER ?= smpeer
PEER_BIN_DIR ?= /tmp/sm-peer
PEER_PKGS := $(addprefix ./,$(addsuffix /...,$(wildcard internal/daemon internal/client internal/api)))

# Go refuses to test or lint a tree without packages; skip until the first one lands.
HAS_GO := $(shell find . -name '*.go' -not -path './.git/*' -print -quit)
IF_GO := @[ -z "$(HAS_GO)" ] && echo "no Go packages yet; skipping" ||

.DEFAULT_GOAL := help
.PHONY: help build test test-race test-pty test-daemon-peer lint lint-workflows vuln generate integration \
	integration-fixtures cross-build api-check e2e snapshot release-check install-test

help: ## List targets
	@grep -hE '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Build dist/sm
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sm ./cmd/sm

test: ## Run unit tests
	$(IF_GO) go test -count=1 -shuffle=on ./...
	$(IF_GO) go test -count=1 -tags crashpoints ./internal/backup/...

test-race: ## Run unit tests with the race detector
	$(IF_GO) go test -race -count=1 -shuffle=on ./...

test-pty: ## Run the PTY handoff-restoration tests (ubuntu and macOS CI)
	@if [ -d test/integration/pty ]; then go test -race -count=1 -shuffle=on -v ./test/integration/pty/...; \
	else echo "no pty tests yet; skipping"; fi

test-daemon-peer: ## Run the peer-credential tests as a second OS user (Linux only; needs PEER_USER and passwordless sudo)
	@[ "$$(uname -s)" = Linux ] || { echo "test-daemon-peer needs Linux"; exit 1; }
	@id "$(PEER_USER)" >/dev/null || { echo "create the user first: sudo useradd --create-home $(PEER_USER)"; exit 1; }
	install -d -m 0755 "$(PEER_BIN_DIR)"
	CGO_ENABLED=0 go build -trimpath -o "$(PEER_BIN_DIR)/sm" ./cmd/sm
	chmod 0755 "$(PEER_BIN_DIR)/sm"
	SM_PEER_OTHER_USER="$(PEER_USER)" SM_PEER_SM_BIN="$(PEER_BIN_DIR)/sm" \
		go test -race -count=1 -shuffle=on -run PeerCred -v $(PEER_PKGS)

lint: ## Run golangci-lint and the formatter check
	$(IF_GO) { golangci-lint run ./... && golangci-lint fmt --diff; }

lint-workflows: ## Lint the workflow files with actionlint
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) .github/workflows/*.yml

vuln: ## Run govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

generate: ## Regenerate files and fail on drift
	go generate ./...
	@test -z "$$(git status --porcelain)" || { git status --porcelain; echo 'generated files drifted'; exit 1; }

integration: ## Run integration tests
	go test -tags=integration ./test/integration/...

integration-fixtures: ## Run the Docker node-fixture tests (-tags fixtures; needs a local Docker daemon)
	go test -tags=fixtures -p 1 -count=1 -timeout 25m ./test/fixtures/... ./test/integration/...

cross-build: ## Compile for linux/darwin x amd64/arm64 with CGO disabled
	@set -e; for target in $(CROSS_TARGETS); do \
		echo "build $$target"; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go build -trimpath -o /dev/null ./...; \
	done

api-check: ## Check api/openapi.yaml against the route table and wire DTOs, then lint it
	go test -count=1 -run OpenAPI ./internal/api/
	go run github.com/daveshanley/vacuum@$(VACUUM_VERSION) lint -d -e --no-update-check api/openapi.yaml

e2e: ## Not available until M2
	$(NOT_YET)

snapshot: ## Build a snapshot release into dist/ signed with a throwaway key (needs goreleaser v2 and syft)
	packaging/release/snapshot.sh

release-check: ## Verify the signed snapshot in dist/ (archives, SBOMs, checksums, signatures)
	packaging/release/check.sh dist dist/test-trust/allowed_signers

install-test: ## Run the install.sh tamper matrix under dash and bash (needs shellcheck)
	shellcheck -s sh install.sh scripts/join.sh packaging/release/*.sh
	shellcheck -x test/install/*.sh
	@set -e; for sh in dash bash; do test/install/run.sh $$sh; done
