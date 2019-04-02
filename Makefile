TEST ?= $(shell go list ./... | grep -v -e vendor -e keys -e tmp)

INFO_COLOR=\033[1;34m
RESET=\033[0m
BOLD=\033[1m

default: test

test:
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Testing$(RESET)"
	go test -v $(TEST) -timeout=30s -parallel=4
	go test -race $(TEST)

