#!/bin/bash

# Define the parent directory containing the subdirectories
PARENT_DIR="./" # Adjust this to your specific directory

# Iterate over each subdirectory in the specified parent directory
for SUBDIR in "$PARENT_DIR"*/; do
    # Check if the directory is not empty
    if [ -d "$SUBDIR" ]; then
        echo "Processing $SUBDIR"
        cd "$SUBDIR" || exit
        
        # Your commands
        rm -rf elf
        mkdir elf
        cargo clean
	cargo prove build
        
        # Return to the parent directory
        cd ..
    fi
done

echo "All subdirectories processed."
