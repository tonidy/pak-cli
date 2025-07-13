# Security Policy

## Supported Versions

PAK (Password Age Kit) is currently in active development. The following versions are supported with security updates:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.3.x   | :white_check_mark: | Current stable |
| 0.2.x   | :x:                | EOL - Please upgrade |
| < 0.2   | :x:                | EOL - Please upgrade |

**Note**: As PAK is still in pre-1.0 development, we recommend always using the latest 0.3.x version for the most recent security fixes and improvements.

## Security Considerations

PAK is a password manager that handles sensitive cryptographic operations. Key security features include:

- **Age Encryption**: Uses the modern [age encryption](https://age-encryption.org/) format
- **Hardware Security**: Supports YubiKey and macOS Secure Enclave
- **Credential Storage**: Integrates with system credential stores (Keychain, libsecret, Windows Credential Manager)
- **Native Components**: Includes C++ and Swift native bindings for secure operations

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. **Do NOT** create a public GitHub issue

Security vulnerabilities should be reported privately to prevent potential exploitation.

### 2. Report via GitHub Security Advisories

1. Go to the [Security tab](https://github.com/tonidy/pak-cli/security) of our repository
2. Click "Report a vulnerability"
3. Fill out the private vulnerability report form

### 3. Alternative Contact Methods

If you cannot use GitHub Security Advisories, you can:
- Email the maintainer directly (check the repository for contact information)
- Create a private discussion in the repository

### 4. What to Include

When reporting a vulnerability, please include:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could potentially accomplish
- **Reproduction**: Step-by-step instructions to reproduce the issue
- **Environment**: Operating system, Node.js version, PAK version
- **Proof of Concept**: If applicable, a minimal example demonstrating the issue
- **Suggested Fix**: If you have ideas for how to fix the vulnerability

## Response Timeline

- **Initial Response**: Within 48 hours of report
- **Triage**: Within 1 week for severity assessment
- **Fix Development**: 2-4 weeks depending on complexity
- **Release**: Security fixes are released as soon as possible
- **Disclosure**: Public disclosure occurs after fix is released and users have had time to update

## Security Best Practices for Users

When using PAK:

1. **Keep Updated**: Always use the latest version
2. **Secure Your Environment**: Ensure your system is secure and up-to-date
3. **Hardware Keys**: Consider using YubiKey or Secure Enclave for additional security
4. **Backup**: Keep encrypted backups of your password store
5. **Access Control**: Limit access to your password files and directories

## Vulnerability Disclosure Policy

- We follow responsible disclosure practices
- We will acknowledge security researchers who report vulnerabilities
- We aim to fix critical vulnerabilities within 30 days
- We will provide security advisories for all confirmed vulnerabilities

## Security-Related Dependencies

PAK relies on several security-critical dependencies:

- Native cryptographic libraries for Secure Enclave operations
- Age encryption libraries
- System credential store APIs

We regularly audit and update these dependencies to maintain security.

---

**Note**: This is a security-focused project dealing with password management. All security reports are treated with the highest priority. Thank you for helping keep PAK secure! 