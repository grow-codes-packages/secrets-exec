# grow-secrets-exec — local build helpers. CI runs the same commands.
VERSION ?= dev
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
DIST    := dist

.PHONY: build build-all test vet fmt checksums clean

build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o $(DIST)/grow-secrets-exec ./cmd/grow-secrets-exec

build-all:
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" \
	    -o $(DIST)/grow-secrets-exec_linux_$$arch ./cmd/grow-secrets-exec || exit 1; \
	done

test:
	go test -p 2 -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# Same file names and SHA-256 as the GitHub release (same Go version as
# .github/workflows/release.yml): make checksums VERSION=0.1.0
checksums: build-all
	cd $(DIST) && sha256sum grow-secrets-exec_linux_amd64 grow-secrets-exec_linux_arm64 | tee checksums.txt

clean:
	rm -rf $(DIST)
