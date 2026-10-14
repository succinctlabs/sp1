# sp1-build
Lightweight crate used to build SP1 programs. Internal crate that is exposed to users via `sp1-cli`.

Exposes `build_program`, which builds an SP1 program in the local environment or in a docker container with the specified parameters from `BuildArgs`.

## Usage

```rust
use sp1_build::build_program;

build_program(&BuildArgs::default(), Some(program_dir));
```

## Environment Variables

| Variable | Description |
|---|---|
| `SP1_DOCKER` | Set to `false` or `0` to disable Docker builds (default: `true`). |
| `SP1_DOCKER_IMAGE` | Override the Docker image (default: `ghcr.io/succinctlabs/sp1:<tag>`). |
| `SP1_DOCKER_ARGS` | Extra arguments passed to `docker run`. Useful for network configuration or forwarding environment variables into the container. |

### Building behind a proxy

When building behind a network proxy (e.g., Clash, mitmproxy), the Docker container may fail to
fetch dependencies because it cannot reach the proxy running on the host. Use `SP1_DOCKER_ARGS`
to switch to host networking and forward the proxy environment variables:

```bash
SP1_DOCKER_ARGS="--network host -e HTTPS_PROXY=http://127.0.0.1:7890" cargo build -p my-program
```

## Potential Issues

If you attempt to build a program with Docker that depends on a local crate, and the crate is not in
the current workspace, you may run into issues with the docker build not being able to find the crate, as only the workspace root is mounted.

```
error: failed to load manifest for dependency `...`
```

To fix this, you can either:
1. Move the program into the workspace that contains the crate.
2. Build the crate locally instead.
