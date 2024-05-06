SHELL := /bin/bash
.SHELLFLAGS = -e

all:
	@for dir in */ ; do \
		if [ -d "$${dir}program" ]; then \
			echo "Building in $${dir}program..."; \
			cd $${dir}program && cargo prove build || { echo "Failed at command: cd $${dir}program && cargo prove build"; exit 1; }; \
			cd ../../; \
		else \
			echo "No program directory in $${dir}, skipping..."; \
		fi; \
	done

.PHONY: all
