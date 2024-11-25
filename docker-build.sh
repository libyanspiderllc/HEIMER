#!/bin/bash

# Exit on error
set -e

echo "Building Docker image..."
docker build -t heimer-builder .

echo "Extracting binary..."
# Create a temporary container and copy the artifacts
container_id=$(docker create heimer-builder)
docker cp $container_id:/artifacts/. ./dist/
docker rm $container_id

echo "Build complete! Binary is available at: dist/heimer"
echo "You can now run it with: ./dist/heimer"
