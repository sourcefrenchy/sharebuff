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

.PHONY: all macos linux windows build test parity e2e release deploy clean

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

deploy:
	cd worker && CI=true pnpm install && CI=true pnpm exec wrangler deploy

clean:
	rm -rf $(DIST) sharebuff sharebuff-server
