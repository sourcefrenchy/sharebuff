# Sharebuff build & release targets. Binaries are static (CGO_ENABLED=0):
# the linux build runs on any distro (RHEL included), no glibc dependency.

DIST    := dist
LDFLAGS := -s -w
GOBUILD  = CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -trimpath -ldflags '$(LDFLAGS)' -o $(3) $(4)

BINARIES := sharebuff sharebuff-server
PLATFORMS := darwin-arm64 darwin-amd64 linux-amd64 windows-amd64

.PHONY: all build test parity e2e release clean

all: build

## Local development build (host platform)
build:
	go build -o sharebuff ./cmd/sharebuff
	go build -o sharebuff-server ./cmd/sharebuff-server

## Full test suite: Go (with race detector) + JS/Go crypto parity
test:
	go vet ./...
	go test ./... -race -count=1
	node tests/parity.mjs

parity:
	node tests/parity.mjs

## Local end-to-end smoke test against the fallback server
e2e: build
	./tests/e2e.sh

## Cross-compiled release binaries: macOS (arm64 + Intel), Linux (RHEL/any), Windows
release: test
	rm -rf $(DIST)
	mkdir -p $(DIST)
	$(call GOBUILD,darwin,arm64,$(DIST)/sharebuff-darwin-arm64,./cmd/sharebuff)
	$(call GOBUILD,darwin,amd64,$(DIST)/sharebuff-darwin-amd64,./cmd/sharebuff)
	$(call GOBUILD,linux,amd64,$(DIST)/sharebuff-linux-amd64,./cmd/sharebuff)
	$(call GOBUILD,windows,amd64,$(DIST)/sharebuff-windows-amd64.exe,./cmd/sharebuff)
	$(call GOBUILD,darwin,arm64,$(DIST)/sharebuff-server-darwin-arm64,./cmd/sharebuff-server)
	$(call GOBUILD,darwin,amd64,$(DIST)/sharebuff-server-darwin-amd64,./cmd/sharebuff-server)
	$(call GOBUILD,linux,amd64,$(DIST)/sharebuff-server-linux-amd64,./cmd/sharebuff-server)
	$(call GOBUILD,windows,amd64,$(DIST)/sharebuff-server-windows-amd64.exe,./cmd/sharebuff-server)
	@ls -lh $(DIST)

clean:
	rm -rf $(DIST) sharebuff sharebuff-server
