DOCKER_REGISTRY=radixdev.azurecr.io
VERSION=latest
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
IMAGE_NAME=$(DOCKER_REGISTRY)/radix-oauth-guard:$(BRANCH)-$(VERSION)

.PHONY: build
build:
	docker build -t $(IMAGE_NAME) .

.PHONY: push
push:
	az acr login -n $(DOCKER_REGISTRY)
	docker push $(IMAGE_NAME)

.PHONY: test
test:
	go test -cover `go list ./... | grep -v 'pkg/client'`

.PHONY: lint
lint: bootstrap
	golangci-lint run --max-same-issues 0


HAS_GOLANGCI_LINT := $(shell command -v golangci-lint;)

bootstrap:
ifndef HAS_GOLANGCI_LINT
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2
endif
