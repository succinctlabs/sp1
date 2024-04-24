SHELL := /bin/bash

all:
	@for dir in */ ; do \
		echo "Building in $${dir}..."; \
		cd $${dir} && cargo prove build; \
		cd ..; \
	done

.PHONY: all
