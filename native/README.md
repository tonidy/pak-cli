# Native Secure Enclave Addon

This directory contains a native Node.js addon that provides Swift-based Secure Enclave functionality for the pa-lib password manager.

## Architecture

The addon consists of three main components:

1. **Swift Library** (`SecureEnclaveSwift/`) - Core Secure Enclave functionality using Apple's CryptoKit
2. **C++ Bridge** (`src/secure_enclave_addon.cpp`) - Native addon that bridges Swift and JavaScript
3. **JavaScript Wrapper** (`index.js`) - User-friendly JavaScript interface

## Requirements

- macOS 13.0+ (Ventura or later)
- Xcode or Swift toolchain
- Node.js 16.0+
- A Mac with Secure Enclave (Apple Silicon or Intel with T2 chip)

## Building

From the project root:

```bash
npm run build:native
```

Or build manually:

```bash
cd native
npm install
npm run build-swift
npm run build
```

## Usage

The addon provides the following JavaScript functions:

### `isAvailable(): boolean`
Check if Secure Enclave is available on the current device.

### `generateKeyPair(accessControl: string): Promise<{publicKey: Buffer, privateKey: Buffer}>`
Generate a new key pair in the Secure Enclave.

Access control options:
- `"none"` - No access control
- `"passcode"` - Device passcode required
- `"any-biometry"` - Any biometry (Touch ID/Face ID)
- `"any-biometry-or-passcode"` - Either biometry or passcode
- `"any-biometry-and-passcode"` - Both biometry and passcode
- `"current-biometry"` - Current biometry enrollment
- `"current-biometry-and-passcode"` - Current biometry and passcode

### `encrypt(data: Buffer, publicKey: Buffer): Promise<Buffer>`
Encrypt data using a public key.

### `decrypt(ciphertext: Buffer, privateKey: Buffer): Promise<Buffer>`
Decrypt data using a private key from the Secure Enclave.

### `deleteKey(privateKey: Buffer): Promise<boolean>`
Delete a key from the Secure Enclave.

### `getInfo(): object`
Get information about the addon and system.

## Example

```javascript
const secureEnclave = require('./native');

async function example() {
  if (!secureEnclave.isAvailable()) {
    console.log('Secure Enclave not available');
    return;
  }

  // Generate key pair
  const keyPair = await secureEnclave.generateKeyPair('any-biometry-or-passcode');
  
  // Encrypt data
  const data = Buffer.from('Hello, Secure Enclave!');
  const ciphertext = await secureEnclave.encrypt(data, keyPair.publicKey);
  
  // Decrypt data
  const decrypted = await secureEnclave.decrypt(ciphertext, keyPair.privateKey);
  console.log('Decrypted:', decrypted.toString());
}

example().catch(console.error);
```

## Testing

Run the Swift tests:

```bash
cd SecureEnclaveSwift
swift test
```

Test the complete addon:

```bash
npm run test
```

## Troubleshooting

### "Native addon not found"
Make sure you've built the addon:
```bash
npm run build
```

### "Swift is not installed"
Install Xcode from the Mac App Store or download Swift from https://swift.org/download/

### "Secure Enclave not available"
- Ensure you're on a Mac with Secure Enclave support
- Check that the device is unlocked
- Verify biometry is set up if using biometry-based access control

## Security Notes

- Private keys never leave the Secure Enclave
- Access control policies are enforced by the hardware
- Key generation requires user presence/authentication
- All cryptographic operations are performed in the secure hardware

## License

MIT License - see LICENSE file for details. 