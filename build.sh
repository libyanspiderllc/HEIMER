#!/bin/bash

# Exit on error
set -e

echo "Creating virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Building binary..."
pyinstaller build.spec --clean

echo "Binary created at: dist/arcane"

# Optional: Create a release tarball
echo "Creating release tarball..."
cd dist
tar czf arcane-linux.tar.gz arcane
cd ..

echo "Build complete! You can find the binary at dist/arcane"
echo "Or use the tarball at dist/arcane-linux.tar.gz"
