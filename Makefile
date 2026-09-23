GO  ?= go
BIN ?= sund

.PHONY: build vet fmt test test-sys test-all hooks clean

build: ## compile the sund binary (pure-Go SQLite, no cgo)
	CGO_ENABLED=0 $(GO) build -o $(BIN) .

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

test: ## unit suite: Go, in-process (<5s target)
	$(GO) test ./...

test-sys: ## system suite: Python beaconsim drives the real binary (<30s target)
	cd tests && uv run pytest

test-all: test test-sys

hooks: ## install the repo's git hooks (unit suite on pre-commit)
	git config core.hooksPath .githooks
	@echo "hooks installed: core.hooksPath -> .githooks"

clean:
	rm -f $(BIN)
