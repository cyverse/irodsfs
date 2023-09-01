PKG=github.com/cyverse/irodsfs
VERSION=v0.8.18
GIT_COMMIT?=$(shell git rev-parse HEAD)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS?="-X '${PKG}/commons.clientVersion=${VERSION}' -X '${PKG}/commons.gitCommit=${GIT_COMMIT}' -X '${PKG}/commons.buildDate=${BUILD_DATE}'"
GO111MODULE=on
GOPROXY=direct
GOPATH=$(shell go env GOPATH)

.EXPORT_ALL_VARIABLES:

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -ldflags=${LDFLAGS} -o bin/irodsfs ./cmd/

.PHONY: build-release
build-release:
	rm -rf release
	mkdir -p release
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags=${LDFLAGS} -o release/irodsfs ./cmd/
	cd release && tar cvf irodsfs_i386_linux_${VERSION}.tar irodsfs && cd ..
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags=${LDFLAGS} -o release/irodsfs ./cmd/
	cd release && tar cvf irodsfs_amd64_linux_${VERSION}.tar irodsfs && cd ..
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags=${LDFLAGS} -o release/irodsfs ./cmd/
	cd release && tar cvf irodsfs_arm_linux_${VERSION}.tar irodsfs && cd ..
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags=${LDFLAGS} -o release/irodsfs ./cmd/
	cd release && tar cvf irodsfs_arm64_linux_${VERSION}.tar irodsfs && cd ..
	rm release/irodsfs

