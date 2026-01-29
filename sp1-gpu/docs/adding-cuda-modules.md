# Adding New CUDA Modules

This guide explains how to add new CUDA source files and modules to the project. The build system uses CMake with explicit module registration (similar to Rust's module system).

## Quick Reference

| Task | What to do |
|------|------------|
| Add a `.cu` file to existing module | Edit `lib/<module>/CMakeLists.txt` |
| Create a new module | Create folder + `CMakeLists.txt` + update root `CMakeLists.txt` |

## Adding a File to an Existing Module

1. Create your `.cu` file in the appropriate `lib/<module>/` directory
2. Edit `lib/<module>/CMakeLists.txt` and add the filename:

```cmake
add_library(mymodule_objs OBJECT
    existing_file.cu
    your_new_file.cu  # Add this line
)
target_link_libraries(mymodule_objs PRIVATE sp1_gpu_common)
```

That's it! The file will be compiled on the next build.

## Creating a New Module

### Step 1: Create the Module Directory

```bash
mkdir lib/your_module
```

### Step 2: Create the Module's CMakeLists.txt

Create `lib/your_module/CMakeLists.txt`:

```cmake
add_library(your_module_objs OBJECT
    your_file.cu
    # Add more .cu files here as needed
)
target_link_libraries(your_module_objs PRIVATE sp1_gpu_common)
```

The `sp1_gpu_common` library provides:
- Include paths (`include/`, `sppark/`, CUDA toolkit headers)
- Compile definitions (`SPPARK`, `FEATURE_KOALA_BEAR`)

### Step 3: Register the Module in Root CMakeLists.txt

Edit the root `CMakeLists.txt` in two places:

**A. Add the subdirectory** (around line 82, alphabetically sorted):

```cmake
add_subdirectory(lib/algebra)
add_subdirectory(lib/basefold)
# ... other modules ...
add_subdirectory(lib/your_module)  # Add this line
add_subdirectory(lib/zerocheck)
```

**B. Add to ALL_CUDA_OBJECTS** (around line 108):

```cmake
set(ALL_CUDA_OBJECTS
    $<TARGET_OBJECTS:algebra_objs>
    # ... other modules ...
    $<TARGET_OBJECTS:your_module_objs>  # Add this line
    $<TARGET_OBJECTS:zerocheck_objs>
    $<TARGET_OBJECTS:sppark_objs>
)
```

### Step 4: Add Your Source Files

Create your `.cu` files in `lib/your_module/`. Headers typically go in `include/` at the project root.

## Comparison with Rust

| Rust | CMake (this project) |
|------|----------------------|
| `mod.rs` declares submodules | `CMakeLists.txt` lists source files |
| `lib.rs` / `main.rs` at crate root | Root `CMakeLists.txt` lists all modules |
| `cargo` auto-discovers files | Files must be explicitly listed |
| `use crate::module` | `#include "module/header.cuh"` |

## Example: Adding a "hash" Module

```bash
# 1. Create directory
mkdir lib/hash

# 2. Create CMakeLists.txt
cat > lib/hash/CMakeLists.txt << 'EOF'
add_library(hash_objs OBJECT
    sha256.cu
    poseidon.cu
)
target_link_libraries(hash_objs PRIVATE sp1_gpu_common)
EOF

# 3. Create source files
touch lib/hash/sha256.cu lib/hash/poseidon.cu

# 4. Edit root CMakeLists.txt (add_subdirectory and ALL_CUDA_OBJECTS)
```

## Common Issues

### File not being compiled
- Check that the file is listed in the module's `CMakeLists.txt`
- Check that the module is in `add_subdirectory()` in root `CMakeLists.txt`

### Include not found
- Headers in `include/` are automatically available via `sp1_gpu_common`
- Use `#include "subfolder/header.cuh"` relative to `include/`

### Undefined symbol at link time
- Ensure the module's objects are in `ALL_CUDA_OBJECTS`
- For device functions called across files, `-rdc=true` is already enabled

## IDE Support

The build generates `compile_commands.json` for clangd. After adding new files:

1. Rebuild: `cargo build` (or run CMake directly)
2. Restart clangd in your IDE (VS Code: `Ctrl+Shift+P` → "clangd: Restart")

The symlink at project root (`compile_commands.json`) points to the generated file.
