#!/bin/bash
set -e

# Get the version from the command line.
VERSION=$1

# Specify the S3 bucket name
S3_BUCKET="sp1-circuits"

# Check for unstaged changes in the Git repository
if ! git diff --quiet; then
    echo "Error: There are unstaged changes. Please commit or stash them before running this script."
    exit 1
fi

# Get the current git commit hash (shorthand)
COMMIT_HASH=$(git rev-parse --short HEAD)
if [ $? -ne 0 ]; then
    echo "Failed to retrieve Git commit hash."
    exit 1
fi

# Put the version in the build directory
echo "$COMMIT_HASH $VERSION" > ./build/SP1_COMMIT

# Create archives for Groth16, Plonk, and Trusted Setup
GROTH16_ARCHIVE="${VERSION}-groth16.tar.gz"
PLONK_ARCHIVE="${VERSION}-plonk.tar.gz"
TRUSTED_SETUP_ARCHIVE="${VERSION}-trusted-setup.tar.gz"

# Create Groth16 archive
cd ./build/groth16
tar --exclude='srs.bin' --exclude='srs_lagrange.bin' -czvf "../../$GROTH16_ARCHIVE" .
cd ../..
if [ $? -ne 0 ]; then
    echo "Failed to create Groth16 archive."
    exit 1
fi

# Create Plonk archive
cd ./build/plonk
tar --exclude='srs.bin' --exclude='srs_lagrange.bin' -czvf "../../$PLONK_ARCHIVE" .
cd ../..
if [ $? -ne 0 ]; then
    echo "Failed to create Plonk archive."
    exit 1
fi

# Create Trusted Setup archive
cd ./trusted-setup
tar -czvf "../$TRUSTED_SETUP_ARCHIVE" .
cd ..
if [ $? -ne 0 ]; then
    echo "Failed to create Trusted Setup archive."
    exit 1
fi

# Upload Groth16 archive to S3
aws s3 cp "$GROTH16_ARCHIVE" "s3://$S3_BUCKET/$GROTH16_ARCHIVE"
if [ $? -ne 0 ]; then
    echo "Failed to upload Groth16 archive to S3."
    exit 1
fi

# Upload Plonk archive to S3
aws s3 cp "$PLONK_ARCHIVE" "s3://$S3_BUCKET/$PLONK_ARCHIVE"
if [ $? -ne 0 ]; then
    echo "Failed to upload Plonk archive to S3."
    exit 1
fi

# Upload Trusted Setup archive to S3
aws s3 cp "$TRUSTED_SETUP_ARCHIVE" "s3://$S3_BUCKET/$TRUSTED_SETUP_ARCHIVE"
if [ $? -ne 0 ]; then
    echo "Failed to upload Trusted Setup archive to S3."
    exit 1
fi

# Copy Groth16 and Plonk vks to verifier crate
cp ./build/groth16/$VERSION/groth16_vk.bin ../verifier/bn254-vk/groth16_vk.bin
cp ./build/plonk/$VERSION/plonk_vk.bin ../verifier/bn254-vk/plonk_vk.bin

echo "Successfully uploaded build artifacts to S3:"
echo "- s3://$S3_BUCKET/$GROTH16_ARCHIVE"
echo "- s3://$S3_BUCKET/$PLONK_ARCHIVE"
echo "- s3://$S3_BUCKET/$TRUSTED_SETUP_ARCHIVE"

# Clean up local archive files
rm "$GROTH16_ARCHIVE" "$PLONK_ARCHIVE" "$TRUSTED_SETUP_ARCHIVE"
