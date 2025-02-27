#!/bin/bash

# Exit on error
set -e

echo "Building Docker image..."
docker build -f Dockerfile -t heimer-builder .

echo "Extracting binary..."
# Create a temporary container and copy the artifacts
container_id=$(docker create heimer-builder)
docker cp $container_id:/artifacts/heimer ./dist/heimer-alma8
docker rm $container_id

echo "Build complete! Binary is available at: dist/heimer-alma8"
echo "You can now run it with: ./dist/heimer-alma8"
