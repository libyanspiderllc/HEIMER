#!/bin/bash

# Exit on error
set -e

echo "Building Docker image..."
docker build -t arcane-builder .

echo "Extracting binary..."
# Create a temporary container and copy the artifacts
container_id=$(docker create arcane-builder)
docker cp $container_id:/artifacts/. ./dist/
docker rm $container_id

echo "Build complete! Binary is available at: dist/arcane"
echo "You can now run it with: ./dist/arcane"
