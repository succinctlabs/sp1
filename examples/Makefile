SHELL := /bin/bash

all:
	@for dir in */ ; do \
		if [ -d "$${dir}script" ]; then \
			echo "Building in $${dir}script..."; \
			cd $${dir}script && cargo clippy -- -D warnings; \
			cd ../../; \
		else \
			echo "No script directory in $${dir}, skipping..."; \
		fi; \
	done

.PHONY: all
