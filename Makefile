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
GITLEAKS_VERSION := v8.30.1
GO_LICENSES_VERSION := v2.0.1
ALLOWED_LICENSES := Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
LICENSE_OVERRIDES := packaging/release/license-overrides.txt
FUZZ_SHARD ?= 0
FUZZ_SHARDS ?= 1
FUZZTIME ?= 5m
STRESS_COUNT ?= 20
CROSS_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
E2E_DIST ?=
E2E_TIMEOUT ?= 40m
FIXTURE_ARGS ?= -ref main
LIFECYCLE_MODE ?= server
CHECKSUMS ?=
TRUST ?=

PEER_USER ?= smpeer
PEER_BIN_DIR ?= /tmp/sm-peer
PEER_PKGS := $(addprefix ./,$(addsuffix /...,$(wildcard internal/daemon internal/client internal/api)))

# Go refuses to test or lint a tree without packages; skip until the first one lands.
HAS_GO := $(shell find . -name '*.go' -not -path './.git/*' -print -quit)
IF_GO := @[ -z "$(HAS_GO)" ] && echo "no Go packages yet; skipping" ||

.DEFAULT_GOAL := help
.PHONY: help build test test-race test-pty test-daemon-peer lint lint-workflows vuln generate integration \
	integration-fixtures compose-equivalence cross-build api-check e2e e2e-server e2e-install e2e-appliance e2e-upgrade e2e-deploy e2e-mcp snapshot release-check install-test \
	fuzz fuzz-inventory race-stress secrets-scan licenses \
	reproducible migration-fixtures migration-test e2e-lifecycle-container e2e-lifecycle-vm e2e-lifecycle-macos \
	e2e-crash e2e-chain brew-formula docs-check

help: ## List targets
	@grep -hE '^[a-z0-9-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

build: ## Build dist/sm
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sm ./cmd/sm

# The PTY suite measures terminal timing; it runs alone in test-pty, never
# beside the rest of the suite where load makes its deadlines flaky.
UNIT_PKGS = $(shell go list ./... | grep -v /test/integration/pty)

test: ## Run unit tests
	$(IF_GO) go test -count=1 -shuffle=on $(UNIT_PKGS)
	$(IF_GO) go test -count=1 -tags crashpoints ./internal/backup/... ./internal/installer/...

test-race: ## Run unit tests with the race detector
	$(IF_GO) go test -race -count=1 -shuffle=on $(UNIT_PKGS)

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

# The GitHub fakes link sigstore's test CA (x/crypto/openpgp, GO-2026-5932, no fix);
# they are test-only and never reach the sm binary, so they are scanned by vuln-all only.
VULN_PKGS = $(shell go list ./... | grep -vE '/providers/github/ghfake$$|/test/e2e/ghsim$$')

vuln: ## Run govulncheck (everything except the test-only GitHub fakes)
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) $(VULN_PKGS)

vuln-all: ## Run govulncheck over every package, test fakes included (informational)
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

generate: ## Regenerate files and fail on drift
	go generate ./...
	@test -z "$$(git status --porcelain)" || { git status --porcelain; echo 'generated files drifted'; exit 1; }

integration: ## Run integration tests
	go test -tags=integration ./test/integration/...

integration-fixtures: ## Run the Docker node-fixture tests (-tags fixtures; needs a local Docker daemon)
	go test -tags=fixtures -p 1 -count=1 -timeout 25m ./test/fixtures/... ./test/integration/...

compose-equivalence: ## Run the loader-vs-Compose-CLI equivalence corpus against the pinned CLI (-tags fixtures; needs Docker)
	go test -tags=fixtures -p 1 -count=1 -timeout 25m -run ComposeEquivalence ./test/integration/...

cross-build: ## Compile for linux/darwin x amd64/arm64 with CGO disabled
	@set -e; for target in $(CROSS_TARGETS); do \
		echo "build $$target"; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go build -trimpath -o /dev/null ./...; \
	done

api-check: ## Check api/openapi.yaml against the route table and wire DTOs, then lint it
	go test -count=1 -run OpenAPI ./internal/api/
	go run github.com/daveshanley/vacuum@$(VACUUM_VERSION) lint -d -e --no-update-check api/openapi.yaml

e2e: e2e-server e2e-install ## Run the M2 acceptance and security e2e (needs Docker; Debian systemd containers)

e2e-server: ## e2e: remote control (direct and proxy TLS, Dex), local mode, backup/restore, join, secret-leak scans
	go test -tags 'e2e fixtures' -p 1 -count=1 -timeout $(E2E_TIMEOUT) \
		-run 'TestM2_(RemoteControlOverHTTPS|LocalModeWithoutIdP|BackupRestoreFreshHost|JoinEnrollsFixtureNode)$$' ./test/e2e/

e2e-install: ## e2e: curl|bash install on a clean Debian host, tamper matrix (exit 5); E2E_DIST=dist serves a `make snapshot` release
	SM_E2E_DIST="$(if $(E2E_DIST),$(abspath $(E2E_DIST)))" go test -tags e2e -p 1 -count=1 -timeout $(E2E_TIMEOUT) \
		-run 'TestM2_(CurlBashInstallsServer|TamperedReleaseFailsWithExit5|ReviewFirstDetectsModifiedScripts)$$' ./test/e2e/

e2e-appliance: ## e2e: appliance on a simulated Proxmox host (pvesim), release-boundary lifecycle and journal; on arm64 set SM_E2E_PVE_HOST_PLATFORM=linux/amd64
	go test -tags e2e -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run 'TestM3_Appliance|TestM6_Appliance' ./test/e2e/...

e2e-upgrade: ## e2e: upgrade from the M2 release (commit e6d5577; needs the full history), failure boundaries, uninstall
	go test -tags e2e -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run 'TestM3_(Upgrade|Uninstall)' ./test/e2e/

e2e-deploy: ## e2e: CI-gated deployments against a fake GitHub, a virtual Sigstore and a local registry, server and local mode, secret-leak scan
	go test -tags 'e2e fixtures' -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run 'TestM4_' ./test/e2e/

e2e-mcp: ## e2e: MCP over stdio (`sm mcp`) and streamable HTTP (fake authorization server), client registration flow, approval boundary, secret-leak scans
	go test -tags 'e2e fixtures' -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run 'TestE2E_MCP' ./test/e2e/

snapshot: ## Build a snapshot release into dist/ signed with a throwaway key (needs goreleaser v2 and syft)
	packaging/release/snapshot.sh

release-check: ## Verify the signed snapshot in dist/ (archives, SBOMs, checksums, signatures)
	packaging/release/check.sh dist dist/test-trust/allowed_signers

install-test: ## Run the install.sh tamper matrix under dash and bash (needs shellcheck)
	shellcheck -s sh install.sh scripts/join.sh packaging/release/*.sh
	shellcheck -x test/install/*.sh
	@set -e; for sh in dash bash; do test/install/run.sh $$sh; done

fuzz: ## Fuzz one shard of the inventory for FUZZTIME per target (FUZZ_SHARD of FUZZ_SHARDS; default: all targets)
	FUZZTIME=$(FUZZTIME) scripts/fuzz.sh shard $(FUZZ_SHARD) $(FUZZ_SHARDS)

fuzz-inventory: ## Check that every discovered parser is mapped to a Fuzz target and that the seeds reach it
	go test -count=1 ./test/fuzzinv/...
	scripts/fuzz.sh reach

race-stress: ## Hammer the concurrency seams under -race (STRESS_COUNT runs; -tags stress)
	go test -tags stress -race -count=$(STRESS_COUNT) -timeout 30m ./test/stress/...

secrets-scan: ## Scan the full commit history for secrets with gitleaks (needs a full clone)
	go run github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION) git --config .gitleaks.toml --redact --no-banner .

# Modules whose LICENSE go-licenses cannot classify are reviewed in $(LICENSE_OVERRIDES); this target
# checks that every override is itself on the allowlist and ignores exactly those modules.
licenses: ## Check the licences of the modules compiled into sm against the allowlist
	@awk -F'\t' -v allowed=",$(ALLOWED_LICENSES)," '!/^#/ && NF >= 3 && index(allowed, "," $$3 ",") == 0 { print "licenses: override " $$1 " is " $$3 ", outside the allowlist"; bad = 1 } END { exit bad }' $(LICENSE_OVERRIDES)
	go run github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION) check ./cmd/sm \
		--allowed_licenses=$(ALLOWED_LICENSES) \
		--ignore "$$(awk -F'\t' '!/^#/ && NF >= 3 { print $$1 }' $(LICENSE_OVERRIDES) | paste -sd, -)"

reproducible: ## Build the release twice from two clean roots and require byte-identical binaries and archives (needs goreleaser v2, syft)
	packaging/release/reproducible.sh

# Regenerates the committed M1-M5 fixtures with the real milestone binaries (needs Docker and the full history);
# the result is reviewed and committed by hand, never produced in CI.
migration-fixtures: ## Regenerate test/fixtures/migrations with the real milestone binaries (FIXTURE_ARGS, e.g. -only m4,m5)
	go run -tags fixturegen,fixtures ./test/fixtures/migrations/gen $(FIXTURE_ARGS)

migration-test: ## Migrate and restore the committed M1-M5 fixtures and check their provenance (needs the full history)
	go test -race -count=1 -shuffle=on -run '^Test(MigrationFixtures|FixtureProvenanceRules|ParseProvenance)' ./test/integration/
	go test -tags fixturegen,fixtures -count=1 -shuffle=on ./test/fixtures/migrations/gen/

e2e-lifecycle-container: ## e2e: install, upgrade, backup, restore, uninstall, purge in one Debian systemd container (needs Docker)
	go test -tags e2e -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run '^TestM6_LifecycleServerContainer$$' ./test/e2e/

# The two host targets mutate the machine they run on. Only they compile the host-mutating tests, and
# the guard (ADR-0036) refuses anything but a disposable runner. The caller must export SM_E2E_VM=1.
e2e-lifecycle-vm: ## e2e on a DISPOSABLE Linux runner: real host lifecycle, LIFECYCLE_MODE=server (root) or local-client
	@[ "$$SM_E2E_VM" = 1 ] || { echo "e2e-lifecycle-vm mutates this machine: export SM_E2E_VM=1 on a disposable runner"; exit 1; }
	@case "$(LIFECYCLE_MODE)" in \
	server) sudo -E env "PATH=$$PATH" "GOCACHE=$$(go env GOCACHE)" "GOMODCACHE=$$(go env GOMODCACHE)" \
		go test -tags 'e2e hostlifecycle' -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run '^TestLifecycleVM_Server$$' -v ./test/e2e/ ;; \
	local-client) go test -tags 'e2e hostlifecycle' -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run '^TestLifecycleVM_LocalClient$$' -v ./test/e2e/ ;; \
	*) echo "LIFECYCLE_MODE must be server or local-client"; exit 1 ;; \
	esac

e2e-lifecycle-macos: ## e2e on a DISPOSABLE macOS runner: real launchd lifecycle in local-client mode
	@[ "$$SM_E2E_VM" = 1 ] || { echo "e2e-lifecycle-macos mutates this machine: export SM_E2E_VM=1 on a disposable runner"; exit 1; }
	go test -tags 'e2e hostlifecycle' -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run '^TestLifecycleMacOS_LocalClient$$' -v ./test/e2e/

e2e-crash: ## e2e: kill the installer at all 20 upgrade crash points and rerun (needs Docker; about 11 minutes)
	go test -tags e2e -p 1 -count=1 -timeout 90m -run 'TestM6_CrashUpgrade' ./test/e2e/

e2e-chain: ## e2e: upgrade the M2 fixture world to the latest release in one jump (needs Docker and the full history)
	go test -tags 'e2e fixtures' -p 1 -count=1 -timeout $(E2E_TIMEOUT) -run '^TestM6_UpgradeChain' ./test/e2e/

brew-formula: ## Render the Homebrew formula on stdout: make -s brew-formula CHECKSUMS=dist/checksums.txt [TRUST=dist/allowed_signers]
	@[ -n "$(CHECKSUMS)" ] || { echo "usage: make -s brew-formula CHECKSUMS=checksums.txt [TRUST=allowed_signers]"; exit 1; }
	@packaging/release/brew-formula.sh "$(CHECKSUMS)" $(TRUST)

docs-check: ## Check that the docs cite existing tests and jobs and that their links resolve
	go test -count=1 -shuffle=on ./test/docs/...
