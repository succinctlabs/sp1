APP_NAME=sp1-recursion-gnark-ffi
TARGET=x86_64-unknown-linux-gnu

build-image:
	cargo build --target "$(TARGET)" --release --bin "$(APP_NAME)"
	tar c "../../target/$(TARGET)/release/$(APP_NAME)" ./Dockerfile | docker build -t "$(APP_NAME)" -

run-image:
	docker run --rm "$(APP_NAME)" $(ARGS)

remove-image:
	docker rmi "$(APP_NAME)"

.PHONY: build-image run-image remove-image
