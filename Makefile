PROTOS_IMAGE ?= trufflesecurity/protos:1.21-0

.PHONY: check
.PHONY: lint
.PHONY: test
.PHONY: test-race
.PHONY: run
.PHONY: install
.PHONY: protos
.PHONY: protos-windows
.PHONY: vendor
.PHONY: dogfood

dogfood:
	CGO_ENABLED=0 go run . git file://. --json --debug

install:
	CGO_ENABLED=0 go install .

check:
	go fmt $(shell go list ./... | grep -v /vendor/)
	go vet $(shell go list ./... | grep -v /vendor/)

lint:
	golangci-lint run --enable bodyclose --enable exportloopref --out-format=colored-line-number --timeout 10m

test-failing:
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/) | grep FAIL

test:
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/ | grep -v pkg/detectors)

test-integration:
	CGO_ENABLED=0 go test -timeout=5m -tags=integration $(shell go list ./... | grep -v /vendor/ | grep -v pkg/detectors)

test-race:
	CGO_ENABLED=1 go test -timeout=5m -race $(shell go list ./... | grep -v /vendor/ | grep -v pkg/detectors)

test-detectors:
	CGO_ENABLED=0 go test -tags=detectors -timeout=5m $(shell go list ./... | grep pkg/detectors)

test-community:
	CGO_ENABLED=0 go test -timeout=5m $(shell go list ./... | grep -v /vendor/ | grep -v pkg/detectors | grep -v pkg/sources)

bench:
	CGO_ENABLED=0 go test $(shell go list ./pkg/secrets/... | grep -v /vendor/) -benchmem -run=xxx -bench .

run:
	CGO_ENABLED=0 go run . git file://. --json

run-debug:
	CGO_ENABLED=0 go run . git file://. --json --debug

protos:
	docker run --rm -u "$(shell id -u)" -v "$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; /pwd/scripts/gen_proto.sh"

protos-windows:
	docker run --rm -v "$(shell cygpath -w $(shell pwd))":/pwd "${PROTOS_IMAGE}" bash -c "cd /pwd; ./scripts/gen_proto.sh"

release-protos-image:
	docker buildx build --push --platform=linux/amd64,linux/arm64 \
	-t trufflesecurity/protos:1.21-0 -f hack/Dockerfile.protos .

snifftest:
	./hack/snifftest/snifftest.sh

test-release:
	goreleaser release --rm-dist --skip-publish --snapshot


PROJECT := trufflehog
REVISION := latest

BUILD_VENDOR := go mod vendor && chmod -R +w vendor

install_deps:
	docker compose -f infrastructure/build.yaml --project-name $(PROJECT) \
	run --rm build-env /bin/sh -c "apk update && apk add git && $(BUILD_VENDOR)"

build: install_deps
	docker compose -f infrastructure/build.yaml --project-name $(PROJECT) \
	run --rm build-env /bin/sh -c "go build -mod=vendor -o ./bin/$(PROJECT)"