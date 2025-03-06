#!/bin/bash

elf_path="${1:-/path/to/elf/riscv32im-succinct-zkvm-elf}"

if [ ! -f "$elf_path" ]; then
    echo "ERROR: ELF file not found at $elf_path"
    exit 1
else
    echo "ELF file found at $elf_path"
    exit 0
fi
