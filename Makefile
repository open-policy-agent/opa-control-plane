CGO_ENABLED ?= 0
GOFLAGS ?= "-buildmode=exe"
GO := CGO_ENABLED=$(CGO_ENABLED) GOFLAGS="$(GOFLAGS)" go

VERSION := $(shell ./build/get-build-version.sh)

DOCKER := docker

DOCKER_UID ?= 0
DOCKER_GID ?= 0

REPOSITORY ?= openpolicyagent
IMAGE := $(REPOSITORY)/opa-control-plane

GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

GO_TAGS := -tags=

BIN := opactl_$(GOOS)_$(GOARCH)

ifeq ($(shell tty > /dev/null && echo 1 || echo 0), 1)
DOCKER_FLAGS := --rm -it
else
DOCKER_FLAGS := --rm
endif

LDFLAGS := ""

GOLANGCI_LINT_VERSION := v2.4.0

DOCKER_RUNNING ?= $(shell docker ps >/dev/null 2>&1 && echo 1 || echo 0)

# Get current git SHA and add -dirty if there are uncommitted changes
VCS := $(shell git rev-parse --short HEAD)$(shell test -n "$(shell git status --porcelain)" && echo -dirty)
GOVERSION := $(shell awk '/^go /{print $$2; exit}' go.mod)

# Supported platforms to include in image manifest lists
DOCKER_PLATFORMS := linux/amd64,linux/arm64

######################################################
#
# Development targets
#
######################################################

.PHONY: all
all: build test

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: build
build: go-build

.PHONY: build-linux
build-linux:
	@$(MAKE) build GOOS=linux CGO_ENABLED=0

.PHONY: test
test: go-test go-bench library-test authz-test

.PHONY: go-build
go-build: generate
	$(GO) build $(GO_TAGS) -o $(BIN) -ldflags $(LDFLAGS)

.PHONY: go-test
go-test: generate
	$(GO) test $(GO_TAGS) ./...

.PHONY: go-bench
go-bench: generate
	$(GO) test -benchmem -run=- -bench=. $(GO_TAGS) ./...

.PHONY: go-e2e-migrate-test
go-e2e-migrate-test: generate
	$(GO) test -tags=migration_e2e ./e2e -v -run '^TestMigration/'

.PHONY: ci-build-linux
ci-build-linux:
	$(MAKE) ci-go-build-linux GOARCH=arm64
	$(MAKE) ci-go-build-linux GOARCH=amd64

.PHONY: docker-login
docker-login:
	@echo "Docker Login..."
	@echo ${DOCKER_PASSWORD} | $(DOCKER) login -u ${DOCKER_USER} --password-stdin

.PHONY: image
image:
	@$(MAKE) ci-go-build-linux
	@$(MAKE) image-quick

.PHONY: image-quick
image-quick: image-quick-$(GOARCH)

.PHONY: image-quick-%
image-quick-%:
	$(DOCKER) build \
			-t $(IMAGE):$(VERSION) \
			--build-arg BASE=chainguard/static:latest \
			--platform=linux/$(GOARCH) \
			-f Dockerfile \
			.

.PHONY: push-manifest-list-%
push-manifest-list-%:
	$(DOCKER) buildx build \
		--platform=$(DOCKER_PLATFORMS) \
		--push \
		-t $(IMAGE):$* \
		--build-arg BASE=chainguard/static:latest \
		-f Dockerfile \
		.

.PHONY: push-image
push-image: docker-login push-manifest-list-$(VERSION)

.PHONY: deploy-ci
deploy-ci: docker-login ci-build-linux push-manifest-list-$(VERSION) push-manifest-list-edge

.PHONY: release-ci
release-ci: docker-login ci-build-linux push-manifest-list-$(VERSION) push-manifest-list-latest

.PHONY: libary-test
library-test:
	make -C libraries/entitlements-v1 test
	make -C libraries/envoy-v2.0 test
	make -C libraries/envoy-v2.1 test
	make -C libraries/kong-gateway-v1 test
	make -C libraries/kubernetes-v2 test
	make -C libraries/terraform-v2.0 test

.PHONY: authz-test
authz-test:
	$(GO) run github.com/open-policy-agent/opa test -b ./internal/authz


CI_GOLANG_DOCKER_MAKE := $(DOCKER) run \
        $(DOCKER_FLAGS) \
        -u $(DOCKER_UID):$(DOCKER_GID) \
        -v $(PWD):/src \
        -w /src \
        -e GOCACHE=/src/.go/cache \
        -e CGO_ENABLED=$(CGO_ENABLED) \
		-e GOARCH=$(GOARCH) \
        golang:$(GOVERSION)

.PHONY: ci-go-%
ci-go-%:
	$(CI_GOLANG_DOCKER_MAKE) /bin/bash -c "git config --global --add safe.directory /src && make $*"

.PHONY: clean
clean:
	rm -f opactl_*_*

.PHONY: check
check:
ifeq ($(DOCKER_RUNNING), 1)
	docker run --rm -v $(shell pwd):/app:ro,Z -w /app golangci/golangci-lint:${GOLANGCI_LINT_VERSION} golangci-lint run -v
else
	@echo "Docker not installed or running. Skipping golangci run."
endif
