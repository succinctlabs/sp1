# sp1-build
Lightweight crate used to build SP1 programs. Also used by `sp1-cli`.

Exposes `build_program`, which builds an SP1 program in the local environment. To configure the 
build with additional arguments, use `build_program_with_args`.

## Usage

```rust
use sp1_build::{build_program, build_program_with_args};

build_program("path/to/program");

build_program_with_args("path/to/program", &BuildArgs::default());
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
