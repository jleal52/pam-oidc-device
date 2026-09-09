.PHONY: test lint vet so so-native package integration

test:
	go test ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

so:
	@echo "TODO: implemented in a later task"

so-native:
	@echo "TODO: implemented in a later task"

package:
	@echo "TODO: implemented in a later task"

integration:
	@echo "TODO: implemented in a later task"
