#!/bin/bash

# Build script for native Secure Enclave addon
# Requires macOS with Xcode and Swift toolchain

set -e

echo "Building native Secure Enclave addon..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "Warning: Native Secure Enclave addon only supports macOS"
    echo "Skipping native build..."
    exit 0
fi

# Check if Swift is available
if ! command -v swift &> /dev/null; then
    echo "Error: Swift is not installed. Please install Xcode or Swift toolchain."
    exit 1
fi

# Check if node-gyp is available
if ! command -v node-gyp &> /dev/null; then
    echo "Installing node-gyp..."
    npm install -g node-gyp
fi

# Navigate to native directory
cd native

# Install native dependencies
echo "Installing native dependencies..."
npm install

# Build Swift library
echo "Building Swift library..."
cd SecureEnclaveSwift
swift build -c release

# Test Swift library (optional)
if [[ "$1" == "--test" ]]; then
    echo "Testing Swift library..."
    swift test
fi

cd ..

# Build native addon
echo "Building native addon..."
npm run build

echo "Native addon build complete!"

# Test the addon
echo "Testing native addon..."
node -e "
try {
    const addon = require('./index.js');
    console.log('Addon info:', addon.getInfo());
    console.log('Secure Enclave available:', addon.isAvailable());
} catch (error) {
    console.error('Error testing addon:', error.message);
    process.exit(1);
}
"

echo "Native addon test complete!" 