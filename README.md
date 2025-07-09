# PAK (Password Age Kit) - JavaScript Password Manager

A simple, secure password manager in JavaScript using [age encryption](https://age-encryption.org/). This is a TypeScript port of the shell script from [https://github.com/tonidy/pa-cli](https://github.com/tonidy/pa-cli), providing cross-platform compatibility and modern features.

## Features

- **Age Encryption**: Uses the modern age encryption format for secure password storage
- **Cross-Platform**: Works on macOS, Linux, and Windows (including WSL)
- **Hardware Support**: Supports YubiKey, Secure Enclave (macOS), and other age plugins
- **Git Integration**: Automatic git tracking of password changes
- **Credential Storage**: Integrates with system credential stores (Keychain, libsecret, Credential Manager)
- **Fuzzy Search**: Interactive password selection with fzf
- **CLI Interface**: Command-line interface matching the original pa script

## Installation

```bash
npm install -g @kdbx/pak-lib
```

Or use directly with npx:

```bash
npx @kdbx/pak-lib --help
```

## Usage

### Basic Commands

```bash
# Add a password (will prompt to generate or enter manually)
pa add mysite

# Show a password
pa show mysite

# List all passwords
pa list

# Edit a password with your $EDITOR
pa edit mysite

# Delete a password
pa del mysite

# Search passwords with fzf
pa find

# Search and perform action
pa find show    # or edit, del
```

### Advanced Usage

```bash
# Git operations
pa git log
pa git status

# Version information
pa version
```

### Environment Variables

Configure the password manager behavior with these environment variables:

```bash
# Data directory (default: ~/.local/share/pa)
export PA_DIR=~/.local/share/pa

# Default password length (default: 50)
export PA_LENGTH=50

# Password character pattern (default: A-Za-z0-9-_)
export PA_PATTERN=A-Za-z0-9-_

# Disable git tracking
export PA_NOGIT=1

# Disable system credential storage
export PA_NO_KEYRING=1

# Editor command (default: vi)
export EDITOR=nano
```

## Platform Support

### macOS
- **Keychain Integration**: Stores encryption key passphrases in macOS Keychain
- **Secure Enclave**: Supports age-plugin-se for hardware-backed encryption
- **Touch ID/Face ID**: Biometric authentication for Secure Enclave keys

### Linux
- **libsecret Integration**: Uses secret-tool for credential storage
- **Memory Storage**: Prefers /dev/shm for temporary files

### Windows
- **Credential Manager**: Integrates with Windows Credential Manager
- **WSL Support**: Full support for Windows Subsystem for Linux
- **PowerShell Integration**: Uses PowerShell for credential operations

### Hardware Support
- **YubiKey**: Supports age-plugin-yubikey for hardware security keys
- **FIDO2**: Compatible with FIDO2 security keys
- **Age Plugins**: Extensible through age plugin system

## Security Features

- **Age Encryption**: Modern, secure file encryption
- **Secure Random Generation**: Cryptographically secure password generation
- **Memory Protection**: Temporary files stored in secure locations
- **Key Management**: Automatic key generation and management
- **Passphrase Protection**: Optional passphrase protection for keys
- **Hardware Security**: Support for hardware-backed encryption

## File Structure

```
~/.local/share/pa/
├── identities          # Age private keys
├── recipients          # Age public keys
└── passwords/          # Encrypted password files
    ├── .git/           # Git repository (optional)
    ├── .gitattributes  # Git diff configuration
    └── *.age           # Encrypted password files
```

## API Usage

You can also use PAK programmatically:

```javascript
import { PasswordManager } from '@kdbx/pak-lib';

const pm = new PasswordManager();

// Add a password
await pm.add('mysite', { generate: true, length: 32 });

// Retrieve a password
const password = await pm.show('mysite');

// List all passwords
const passwords = await pm.list();

// Delete a password
await pm.delete('mysite');
```

## Development

### Building from Source

```bash
git clone https://github.com/tonidy/pak-lib.git
cd pak-lib
npm install
npm run build
```

### Running Tests

```bash
npm test
```

### Development Mode

```bash
npm run dev -- add mysite
```

## Dependencies

- **age-encryption**: TypeScript implementation of age encryption
- **commander**: Command-line interface framework
- **keytar**: Cross-platform credential storage (optional)

## Optional Dependencies

- **fzf**: Fuzzy finder for password search
- **git**: Version control for password tracking
- **age-plugin-se**: Secure Enclave support (macOS)
- **age-plugin-yubikey**: YubiKey support

## Compatibility

- **Node.js**: 16.0.0 or higher
- **Operating Systems**: macOS, Linux, Windows
- **Age Format**: Compatible with age 1.0+ and rage

## Migration from Shell Script

If you're migrating from the original pa shell script:

1. Your existing password store is compatible
2. Set `PA_DIR` to your existing password directory
3. Age keys and encrypted files work without modification
4. Git history is preserved

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security

If you discover a security vulnerability, please email security@example.com instead of using the issue tracker.

## Acknowledgments

- Shell script source: [pa-cli](https://github.com/tonidy/pa-cli) by tonidy
- Original [pa](https://github.com/biox/pa) shell script by biox
- [age encryption](https://age-encryption.org/) by Filippo Valsorda
- [typage](https://github.com/FiloSottile/typage) TypeScript implementation 