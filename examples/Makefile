SHELL := /bin/bash
.SHELLFLAGS = -e

all:
	@for dir in */ ; do \
		if [ -d "$${dir}script" ]; then \
			echo "Building in $${dir}script..."; \
			cd $${dir}script && cargo check || { echo "Failed at command: cd $${dir}script && cargo check"; exit 1; }; \
			cd ../../; \
		else \
			echo "No program directory in $${dir}, skipping..."; \
		fi; \
	done

.PHONY: all
