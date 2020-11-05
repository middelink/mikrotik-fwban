.PHONY: clean build test

MAIN_DIRECTORY := .
BIN_OUTPUT := $(if $(filter $(shell go env GOOS), windows), mikrotik-fwban.exe, mikrotik-fwban)

TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))

default: clean test build

clean:
	@echo BIN_OUTPUT: ${BIN_OUTPUT}
	rm -rf ${BIN_OUTPUT} coverage.out

build: clean
	@echo Version: $(VERSION)
	go build -v -trimpath -ldflags '-X "main.version=${VERSION}"' -o ${BIN_OUTPUT} ${MAIN_DIRECTORY}

test: clean
	go test -cover ./...
