SHELL := /bin/bash

all:
	@for dir in */ ; do \
		if [ "$${dir}" == "target/" ] || [ "$${dir}" == "common/" ]; then \
		    continue; \
		fi; \
		echo "Building in $${dir}..."; \
		cd $${dir} && cargo prove build --output-directory $${dir}/elf || { echo "Failed at command: cd $${dir} && cargo prove build"; exit 1; }; \
		cd ..; \
	done

.PHONY: all
