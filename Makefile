# Pure-Go builds: static binaries, no libsecp256k1/libsqlite C toolchain needed.
export CGO_ENABLED=0

.PHONY: test test-short vet build

test:
	go test -count=1 -timeout 20m ./...

test-short:
	go test -short -count=1 ./...

vet:
	go vet ./...

build:
	go build -o bin/ ./cmd/...
