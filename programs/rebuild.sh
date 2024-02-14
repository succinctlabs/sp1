#!/bin/bash

DIR=$1

# Iterate over each subdirectory in the specified directory
for d in "$DIR"/*/ ; do
    echo "Entering directory $d"
    cd "$d"
    
    # Remove the elf directory if it exists
    if [ -d "elf" ]; then
        rm -rf elf
    fi
    
    # Create a new elf directory
    mkdir elf
    
    # Run cargo build
    cargo build
    
    # Go back to the original directory
    cd ..
done
