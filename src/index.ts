/**
 * PAK (Password Age Kit) - Password Manager
 * Main entry point for the password manager
 */

// Main password manager class
export { PasswordManager } from './password-manager';

// Crypto and encryption
export { AgeManager } from './crypto/age-manager';
export { AppleSecureEnclave, SecureEnclaveManager } from './crypto/secure-enclave-manager';

// Platform utilities
export { PlatformDetector } from './platform/platform-detector';

// Core types
export {
  PakConfig,
  VersionInfo,
  GitInfo,
  OSType,
  PasswordEntry,
  EncryptionKeys,
  CommandOptions,
  FindOptions,
  AgePluginConfig,
  PlatformCapabilities,
  PasswordManagerOptions,
  CredentialService,
  GitRepository,
  AgeEncryption,
  RandomGenerator,
  UserInteraction,
  FileSystem,
  PaError,
  // Apple Secure Enclave types
  SecureEnclaveConfig,
  SecureEnclaveKeyPair,
  SecureEnclaveCapabilities,
  AppleSecureEnclaveAPI
} from './types';

// Version constant
export const VERSION = '1.0.0'; 