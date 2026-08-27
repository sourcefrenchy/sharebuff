# Sharebuff build & release targets. Binaries are static (CGO_ENABLED=0):
# the linux build runs on any distro (RHEL included), no glibc dependency.
#
#   make all       - cross-compile every platform into dist/ (macos+linux+windows)
#   make macos     - dist/ binaries for macOS (Apple Silicon + Intel)
#   make linux     - dist/ binaries for Linux (static, RHEL-compatible)
#   make windows   - dist/ binaries for Windows
#   make build     - host-platform dev binaries in the repo root
#   make test      - go vet + go test -race + JS/Go crypto parity
#   make e2e       - full local lifecycle against the fallback server
#   make release   - test, then make all
#   make deploy    - deploy the Cloudflare Worker (needs wrangler login)
#   make clean

DIST    := dist
LDFLAGS := -s -w
GOBUILD  = CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$(3) ./cmd/$(4)

.DEFAULT_GOAL := help
.PHONY: help all macos linux windows build test parity e2e release deploy wordlist jsvectors integrity clean

help:
	@echo "Sharebuff — one-shot end-to-end-encrypted drop (clipboard text & files)"
	@echo ""
	@echo "  make build      build ./sharebuff (CLI) and ./sharebuff-server for this machine"
	@echo "  make all        cross-compile every release binary into dist/ (macOS+Linux+Windows)"
	@echo "  make macos      release binaries for macOS (Apple Silicon + Intel)"
	@echo "  make linux      release binaries for Linux (static, RHEL-compatible, amd64+arm64)"
	@echo "  make windows    release binaries for Windows"
	@echo "  make test       go vet + unit tests (-race) + JS/Go crypto parity"
	@echo "  make e2e        full local lifecycle test against the fallback server"
	@echo "  make release    test, then all"
	@echo "  make deploy     deploy the Cloudflare Worker (pnpm + wrangler)"
	@echo "  make clean      remove built binaries and dist/"
	@echo ""
	@echo "Quick start:  make build && ./sharebuff"

all: macos linux windows
	@ls -lh $(DIST)

macos:
	@mkdir -p $(DIST)
	$(call GOBUILD,darwin,arm64,sharebuff-darwin-arm64,sharebuff)
	$(call GOBUILD,darwin,amd64,sharebuff-darwin-amd64,sharebuff)
	$(call GOBUILD,darwin,arm64,sharebuff-server-darwin-arm64,sharebuff-server)
	$(call GOBUILD,darwin,amd64,sharebuff-server-darwin-amd64,sharebuff-server)

linux:
	@mkdir -p $(DIST)
	$(call GOBUILD,linux,amd64,sharebuff-linux-amd64,sharebuff)
	$(call GOBUILD,linux,arm64,sharebuff-linux-arm64,sharebuff)
	$(call GOBUILD,linux,amd64,sharebuff-server-linux-amd64,sharebuff-server)
	$(call GOBUILD,linux,arm64,sharebuff-server-linux-arm64,sharebuff-server)

windows:
	@mkdir -p $(DIST)
	$(call GOBUILD,windows,amd64,sharebuff-windows-amd64.exe,sharebuff)
	$(call GOBUILD,windows,amd64,sharebuff-server-windows-amd64.exe,sharebuff-server)

build:
	go build -o sharebuff ./cmd/sharebuff
	go build -o sharebuff-server ./cmd/sharebuff-server

test:
	go vet ./...
	go test ./... -race -count=1
	node tests/parity.mjs

parity:
	node tests/parity.mjs

e2e: build
	./tests/e2e.sh

release: test all

deploy: integrity
	cd worker && CI=true pnpm install && CI=true pnpm exec wrangler deploy

## Write web/integrity.json (SHA-256 of every page file) and print it; the
## page footer shows the app.js prefix, README explains how to verify.
integrity:
	@python3 -c "import hashlib,json;fs=['app.js','crypto.js','scrypt.js','wordlist.js','style.css','index.html'];d={'generated_by':'make integrity','sha256':{f:hashlib.sha256(open('web/'+f,'rb').read()).hexdigest() for f in fs}};open('web/integrity.json','w').write(json.dumps(d,indent=2)+'\n');print(json.dumps(d['sha256'],indent=2))"

## Regenerate browser-encrypted vectors that the Go tests must decrypt
jsvectors:
	node tests/gen-js-vectors.mjs

## Regenerate web/wordlist.js from the CLI wordlist (single source of truth)
wordlist:
	{ echo "// Generated from cmd/sharebuff/wordlist.txt (EFF long list, 4–8 letters, 6,134 words)."; \
	  echo "// Regenerate: make wordlist. tests/parity.mjs asserts this matches the Go list."; \
	  printf "export const WORDS = "; python3 -c "import json;print(json.dumps(open('cmd/sharebuff/wordlist.txt').read().split()))"; echo ";"; } > web/wordlist.js

clean:
	rm -rf $(DIST) sharebuff sharebuff-server
