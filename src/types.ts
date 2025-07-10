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
  seAccessControl?: string;
  seAutoConfirm?: boolean;
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
  accessControl?: 'any-biometry' | 'any-biometry-or-passcode' | 'passcode' | 'current-biometry';
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