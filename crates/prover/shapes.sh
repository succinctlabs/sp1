#!/bin/bash

# S3 bucket name.
S3_BUCKET="sp1-circuits"

# Check for unstaged changes in the Git repository
if ! git diff --quiet; then
    echo "Error: There are unstaged changes. Please commit or stash them before running this script."
    exit 1
fi

# Get the current short Git reference.
GIT_REF=$(git rev-parse --short HEAD)

# Upload allowed_vk_map.bin.
aws s3 cp allowed_vk_map.bin "s3://${S3_BUCKET}/shapes-${GIT_REF}/allowed_vk_map.bin"

# Upload dummy_vk_map.bin.
aws s3 cp dummy_vk_map.bin "s3://${S3_BUCKET}/shapes-${GIT_REF}/dummy_vk_map.bin"

# Print the uploaded shapes.
echo "\n"
echo "Successfully uploaded shapes to s3:"
echo "- https://${S3_BUCKET}.s3.us-east-2.amazonaws.com/shapes-${GIT_REF}/allowed_vk_map.bin"
echo "- https://${S3_BUCKET}.s3.us-east-2.amazonaws.com/shapes-${GIT_REF}/dummy_vk_map.bin"
echo "Shape Version: ${GIT_REF}"