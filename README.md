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
npm install -g @kdbx/pak
```

Or use directly with npx:

```bash
npx @kdbx/pak --help
```

> **Note**: Both `pa` and `pak` commands are available after installation. In Indonesia, using "Pak" isn’t just about calling someone "sir" — it’s about showing respect, building community, and being part of a culture that values kindness and humility.

>So whether you're asking for help or giving a command, saying "Pak" makes everything sound more friendly and respectful — just like how locals do it.

> And now, you're using pak as a command-line tool 😄.

## Usage

### Basic Commands

```bash
# Add a password (will prompt to generate or enter manually)
pak add mysite

# Show a password
pak show mysite

# List all passwords
pak list

# Edit a password with your $EDITOR
pak edit mysite

# Delete a password
pak del mysite

# Search passwords with fzf
pak find

# Search and perform action
pak find show    # or edit, del
```

### Advanced Usage

```bash
# Git operations
pak git log
pak git status

# Version information
pak version

# Secure Enclave information (macOS only)
pak se-info

# Convert recipients between formats
pak convert age1se1qfn44rsw... yubikey
pak convert age1yubikey1qfn44rsw... se
```

### Secure Enclave Support (macOS)

PAK provides comprehensive support for Apple's Secure Enclave through age-plugin-se, offering hardware-backed encryption with biometric authentication.

#### Installation

```bash
# Install age-plugin-se
brew install age-plugin-se

# Verify installation
pak se-info
```

#### Features

- **Hardware-backed encryption**: Keys stored in dedicated security hardware
- **Biometric authentication**: Touch ID/Face ID for key access
- **Non-extractable keys**: Private keys cannot be copied or moved
- **Access control options**: Multiple authentication methods available
- **Recipient conversion**: Compatible with age-plugin-yubikey format
- **Native integration**: TypeScript/JavaScript API for direct SE operations (new!)
- **Performance optimized**: Native SE operations avoid CLI overhead
- **Automatic fallback**: Graceful fallback to CLI when native operations fail

#### Access Control Options

1. **any-biometry**: Touch ID or Face ID
2. **any-biometry-or-passcode**: Touch ID/Face ID OR device passcode
3. **passcode**: Device passcode only
4. **current-biometry**: Only currently enrolled biometrics (removing/adding fingerprints affects access)
5. **current-biometry-and-passcode**: Current biometrics AND device passcode

#### Environment Variables

```bash
# Auto-select access control (non-interactive)
export PA_SE_ACCESS_CONTROL=any-biometry-or-passcode

# Auto-confirm Secure Enclave usage (non-interactive)
export PA_SE_AUTO_CONFIRM=1
```

#### Usage Examples

```bash
# Check Secure Enclave support
pak se-info

# Generate identity with custom access control
PA_SE_ACCESS_CONTROL=any-biometry pak add mysite

# Convert between plugin formats
pak convert age1se1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak yubikey
# Output: age1yubikey1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak

# Use converted recipient for encryption on systems without age-plugin-se
echo "secret" | age -r age1yubikey1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak
```

#### Requirements

- macOS 13.0 (Ventura) or later
- Mac with Apple Silicon or Intel T2 Security Chip
- age-plugin-se installed

#### Programmatic API

Use the SE integration programmatically:

```javascript
const { AgeManager, AppleSecureEnclave } = require('@kdbx/pak');

// Initialize with SE support
const config = {
  useAgeBinary: false,  // Use native SE integration
  seAccessControl: 'any-biometry-or-passcode'
};

const ageManager = new AgeManager(config);

// Check SE availability
const isAvailable = await ageManager.isSecureEnclaveAvailable();

// Generate SE identity
const identity = await ageManager.generateSecureEnclaveIdentity('any-biometry');

// Use direct SE module
const secureEnclave = new AppleSecureEnclave({
  accessControl: 'any-biometry-or-passcode',
  recipientType: 'piv-p256',
  useNative: true
});

const keyPair = await secureEnclave.generateKeyPair('any-biometry');
const capabilities = await secureEnclave.getCapabilities();
```

### Configuration

PAK can be configured through environment variables, a `config.json` file, or programmatically.

#### Environment Variables

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

# Force age binary usage (instead of JS library)
export PA_USE_AGE_BINARY=1

# Custom age binary path
export PA_AGE_BINARY_PATH=/opt/homebrew/bin/age

# Secure Enclave access control
export PA_SE_ACCESS_CONTROL=any-biometry-or-passcode

# Auto-confirm Secure Enclave usage
export PA_SE_AUTO_CONFIRM=1
```

#### Configuration File

Create a `config.json` file in your working directory:

```json
{
  "paDir": "~/.local/share/pa",
  "paLength": 50,
  "paPattern": "A-Za-z0-9-_",
  "paNoGit": false,
  "paNoKeyring": false,
  "editor": "vi",
  "useAgeBinary": true,
  "ageBinaryPath": "/opt/homebrew/bin/age",
  "seAccessControl": "any-biometry-or-passcode",
  "seAutoConfirm": false
}
```

#### Priority Order

Configuration is applied in this order (highest priority first):
1. Programmatic options (API usage)
2. `config.json` file
3. Environment variables
4. Default values

#### Age Encryption Backends

PAK supports three age encryption backends:

- **JavaScript Library** (default): Fast, embedded, works without external dependencies
- **Native Secure Enclave**: Direct hardware integration for maximum security (macOS only)
- **Age Binary with Plugins**: Full age plugin support (Secure Enclave, YubiKey, etc.)

**For CLI-based Secure Enclave usage**, you need to install the age-plugin-se:

```bash
# Install age-plugin-se for CLI backend
brew install age-plugin-se
```

The age binary is automatically used when:
- `useAgeBinary: true` is set in config
- `PA_USE_AGE_BINARY=1` environment variable is set
- Secure Enclave or YubiKey recipients/identities are detected
- Hardware encryption is initialized

```bash
# Force age binary usage for full plugin support
export PA_USE_AGE_BINARY=1
pak add mysite  # Will use age binary with Touch ID support
```


## Platform Support

### macOS
- **Keychain Integration**: Stores encryption key passphrases in macOS Keychain
- **Secure Enclave**: Full support for age-plugin-se hardware-backed encryption
- **Touch ID/Face ID**: Biometric authentication for Secure Enclave keys
- **Hardware Security**: Keys stored in dedicated security hardware, cannot be extracted

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
import { PasswordManager } from '@kdbx/pak';

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
git clone https://github.com/tonidy/pak-cli.git
cd pak-cli
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

### Migration from pa-cli with age-plugin-se

If you're already using age-plugin-se with pa-cli:

1. Install PAK and age-plugin-se:
```bash
npm install -g @kdbx/pak
brew install age-plugin-se
```

2. Point to your existing password directory:
```bash
export PA_DIR=/path/to/your/existing/pa/directory
```

3. Verify your Secure Enclave setup:
```bash
pak se-info
```

4. Your existing age-plugin-se identity and recipients files will work seamlessly
5. All encrypted passwords remain accessible with your existing Touch ID/biometric authentication

### Converting Existing Recipients

If you have recipients in different formats, you can convert them:

```bash
# Convert Secure Enclave recipient to YubiKey format
pak convert age1se1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak yubikey

# Convert YubiKey recipient to Secure Enclave format
pak convert age1yubikey1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak se
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security

If you discover a security vulnerability, please email tonidy@users.noreply.github.com instead of using the issue tracker.

## Acknowledgments

- Shell script source: [pa-cli](https://github.com/tonidy/pa-cli) by tonidy
- Original [pa](https://github.com/biox/pa) shell script by biox
- [age encryption](https://age-encryption.org/) by Filippo Valsorda
- [typage](https://github.com/FiloSottile/typage) TypeScript implementation 