PKG=github.com/cyverse/irodsfs
VERSION=v0.13.0
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

