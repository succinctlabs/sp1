# Development

This file contains instructions for working on SP1 locally. It includes steps for building, testing, and formatting the code.

## Requirements

To build and test SP1 locally, you must have [Go](https://go.dev/doc/install) installed.

Install the dependencies:

```bash
make install
```

Build the project:

```bash
make build
```

Run tests:

```bash
make test
```

Run formatting and linting checks:

```bash
make fmt
```

Build the documentation:

```bash
make doc
```

## Git Hooks

We use Git hooks to automatically check formatting and linting before each commit. These are installed as part of `make install`.

You can run the pre-commit hook manually with:

```bash
./.git/hooks/pre-commit
```

## Troubleshooting

If you encounter any issues while building or testing SP1, try the following:

- Ensure you have the correct version of Go installed (refer to go.mod for the required version)
- Run `make clean` to remove build artifacts
- Run `make install` again to reinstall dependencies

## Contribution Workflow

Before submitting a pull request:

1. Ensure your code is properly formatted:  
   ```bash
   make fmt
   ```

2. Run tests and confirm they pass:  
   ```bash
   make test
   ```

3. Make sure your commit messages are clear and descriptive

Thank you for contributing to SP1!
