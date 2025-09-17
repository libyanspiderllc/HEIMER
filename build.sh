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

echo "Binary created at: dist/heimer"

# Optional: Create a release tarball
echo "Creating release tarball..."
cd dist
tar czf heimer-linux.tar.gz heimer
cd ..

echo "Build complete! You can find the binary at dist/heimer"
echo "Or use the tarball at dist/heimer-linux.tar.gz"
