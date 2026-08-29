SHELL := /usr/bin/env bash

APP := ppflight-agent
VERSION := $(shell tr -d '[:space:]' < VERSION)
DIST := dist
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt release-linux-amd64 release-linux-arm64 clean check

build:
	mkdir -p $(DIST)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP) ./cmd/$(APP)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

check: test vet

release-linux-amd64:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-$(VERSION)-linux-amd64 ./cmd/$(APP)
	sha256sum $(DIST)/$(APP)-$(VERSION)-linux-amd64 > $(DIST)/$(APP)-$(VERSION)-linux-amd64.sha256

release-linux-arm64:
	mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(APP)-$(VERSION)-linux-arm64 ./cmd/$(APP)
	sha256sum $(DIST)/$(APP)-$(VERSION)-linux-arm64 > $(DIST)/$(APP)-$(VERSION)-linux-arm64.sha256

clean:
	rm -rf $(DIST)
