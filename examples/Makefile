SHELL := /bin/bash

all:
	@for dir in */ ; do \
		if [ -d "$${dir}program" ]; then \
			echo "Building in $${dir}program..."; \
			cd $${dir}program && cargo clean && cargo prove build && cd ../../; \
		else \
			echo "No program directory in $${dir}, skipping..."; \
		fi; \
	done

.PHONY: all
