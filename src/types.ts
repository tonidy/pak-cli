/**
 * Type definitions for PAK (Password Age Kit) - Password Manager
 */

export interface PakConfig {
  paDir?: string;
  paLength?: number;
  paPattern?: string;
  paNoGit?: boolean;
  paNoKeyring?: boolean;
  editor?: string;
  // Age binary options
  useAgeBinary?: boolean;
  ageBinaryPath?: string;
  // Secure Enclave specific settings
  seAccessControl?: 'none' | 'passcode' | 'any-biometry' | 'any-biometry-or-passcode' | 'any-biometry-and-passcode' | 'current-biometry' | 'current-biometry-and-passcode';
  seAutoConfirm?: boolean;
  useNativeSecureEnclave?: boolean;
  // Backend selection - allows explicit backend choice
  seBackend?: 'native' | 'js' | 'cli' | 'auto';
}

export interface VersionInfo {
  version: string;
  releaseDate: string;
  commit: string;
  isDevelopment: boolean;
}

export interface GitInfo {
  tag?: string;
  commit?: string;
  status?: string;
  date?: string;
}

export type OSType = 'macos' | 'linux' | 'windows' | 'wsl' | 'unknown';

export interface CredentialStoreOptions {
  service: string;
  username: string;
  password?: string;
  osType: OSType;
}

export interface PasswordEntry {
  name: string;
  path: string;
  category?: string;
  createdAt?: Date;
  modifiedAt?: Date;
}

export interface EncryptionKeys {
  identitiesFile: string;
  recipientsFile: string;
  hasIdentity: boolean;
  hasRecipient: boolean;
}

export interface CommandOptions {
  name?: string;
  generate?: boolean;
  length?: number;
  pattern?: string;
  edit?: boolean;
  force?: boolean;
}

export interface FindOptions {
  command?: 'show' | 'edit' | 'del';
  height?: number;
  prompt?: string;
}

export interface AgePluginConfig {
  type: 'secure-enclave' | 'yubikey' | 'standard';
  accessControl?: 'none' | 'passcode' | 'any-biometry' | 'any-biometry-or-passcode' | 'any-biometry-and-passcode' | 'current-biometry' | 'current-biometry-and-passcode';
  name?: string;
  pinPolicy?: 'never' | 'once' | 'always';
  touchPolicy?: 'never' | 'always' | 'cached';
}

export interface PlatformCapabilities {
  credentialStore: boolean;
  secureEnclave: boolean;
  yubikey: boolean;
  fzf: boolean;
  git: boolean;
  age: boolean;
  ageKeygen: boolean;
}

// Apple Secure Enclave specific types
export interface SecureEnclaveConfig {
  accessControl: 'none' | 'passcode' | 'any-biometry' | 'any-biometry-or-passcode' | 'any-biometry-and-passcode' | 'current-biometry' | 'current-biometry-and-passcode';
  recipientType: 'piv-p256' | 'p256tag';
  useNative: boolean;
  backend?: 'native' | 'js' | 'cli' | 'auto';
  preferNative?: boolean;
  fallbackToCli?: boolean;
}

export interface SecureEnclaveKeyPair {
  identity: string;
  recipient: string;
  publicKey: Uint8Array;
  privateKeyRef: string; // Reference to the SE private key
  accessControl: string;
  createdAt: Date;
}

export interface SecureEnclaveCapabilities {
  isAvailable: boolean;
  supportsKeyGeneration: boolean;
  supportsEncryption: boolean;
  supportsDecryption: boolean;
  supportedAccessControls: string[];
  platform: string;
  version?: string;
}

export interface AppleSecureEnclaveAPI {
  // Key management
  generateKeyPair(accessControl: string, format?: 'json' | 'bech32'): Promise<SecureEnclaveKeyPair>;
  loadKeyPair(identity: string): Promise<SecureEnclaveKeyPair>;
  deleteKeyPair(identity: string): Promise<boolean>;
  
  // Cryptographic operations
  encrypt(data: Uint8Array, recipient: string): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array, privateKeyRef: string): Promise<Uint8Array>;
  
  // Utility methods
  isAvailable(): Promise<boolean>;
  getCapabilities(): Promise<SecureEnclaveCapabilities>;
  validateAccessControl(accessControl: string): boolean;
  
  // Age compatibility
  identityToRecipient(identity: string): Promise<string>;
  recipientToAgeFormat(publicKey: Uint8Array, type: 'piv-p256' | 'p256tag'): string;
  parseAgeIdentity(identity: string): { data: Uint8Array; accessControl: string };
}

export interface PasswordManagerOptions {
  config?: PakConfig;
  verbose?: boolean;
  dryRun?: boolean;
}

export interface CredentialService {
  store(service: string, username: string, password: string): Promise<boolean>;
  retrieve(service: string, username: string): Promise<string | null>;
  remove(service: string, username: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}

export interface GitRepository {
  isInitialized(): Promise<boolean>;
  init(): Promise<void>;
  add(file: string): Promise<void>;
  commit(message: string): Promise<void>;
  addAndCommit(file: string, message: string): Promise<void>;
}

export interface AgeEncryption {
  encrypt(data: string, recipientsFile: string): Promise<Uint8Array>;
  decrypt(data: Uint8Array, identitiesFile: string, passphrase?: string): Promise<string>;
  generateIdentity(): Promise<string>;
  generateRecipient(identity: string): Promise<string>;
}

export interface RandomGenerator {
  generateChars(length: number, pattern: string): string;
  generatePassphrase(length: number): string;
}

export interface UserInteraction {
  confirm(message: string): Promise<boolean>;
  prompt(message: string, hidden?: boolean): Promise<string>;
  selectFromList(items: string[], prompt?: string): Promise<string | null>;
}

export interface FileSystem {
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
  write(path: string, data: string): Promise<void>;
  mkdir(path: string): Promise<void>;
  remove(path: string): Promise<void>;
  list(directory: string, pattern?: string): Promise<string[]>;
}

export class PaError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'PaError';
  }
} 