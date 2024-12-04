#!/bin/bash

# Define an array of file paths
paths=(
  "../examples/fibonacci/script/bin/execute.rs"
  "../examples/fibonacci/script/src/main.rs"
  "../examples/fibonacci/script/bin/groth16_bn254.rs"
  "../examples/fibonacci/script/build.rs"
  "../examples/fibonacci/script/src/main.rs"
  "../examples/groth16/program/src/main.rs"
  "../examples/groth16/script/src/main.rs"
  "../examples/io/program/src/main.rs"
  "../examples/cycle-tracking/program/bin/normal.rs"
  "../crates/zkvm/lib/src/lib.rs"
  "../examples/fibonacci/script/bin/compressed.rs"
  "../examples/fibonacci/program/src/main.rs"
)

# Ensure the ./static directory exists
mkdir -p ./static

# Loop over the paths and process each file
for file in "${paths[@]}"; do
  if [[ -f "$file" ]]; then
    # Get the full path and strip everything before 'sp1/'
    stripped_path=$(readlink -f "$file" | sed -e 's|.*sp1/||')

    # Replace slashes with underscores for the target file name
    target_name=$(echo "$stripped_path" | tr '/' '_')

    # Define the target markdown file path
    target="./static/${target_name}.mdx"

    # Write the content into the markdown file
    {
      echo "\`\`\`rust"
      cat "$file"
      echo "\`\`\`"
    } > "$target"

    echo "Processed $file -> $target"
  else
    echo "File not found: $file"
  fi
done
