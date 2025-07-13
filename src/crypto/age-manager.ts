/**
 * Age Encryption Manager
 */

import * as age from 'age-encryption';
import * as fs from 'fs';
import * as path from 'path';
import { PakConfig } from '../types';
import { SecureEnclaveManager, ExtendedSecureEnclaveConfig } from './secure-enclave-manager';

export class AgeManager {
  private identities: string[] = [];
  private recipients: string[] = [];
  private config: PakConfig;
  private secureEnclave?: SecureEnclaveManager;

  /**
   * Initialize AgeManager with updated SE configuration
   */
  constructor(config: PakConfig) {
    this.config = config;
    
    // Initialize Apple Secure Enclave if available and enabled
    if (process.platform === 'darwin' && !config.useAgeBinary) {
      const seConfig: ExtendedSecureEnclaveConfig = {
        accessControl: config.seAccessControl || 'any-biometry-or-passcode',
        recipientType: 'piv-p256',
        useNative: config.useNativeSecureEnclave || false,
        backend: config.useNativeSecureEnclave ? 'native' : 'auto',
        preferNative: config.useNativeSecureEnclave || false,
        fallbackToCli: !config.useNativeSecureEnclave
      };
      this.secureEnclave = new SecureEnclaveManager(seConfig);
    }
  }

  /**
   * Set identities for decryption
   */
  setIdentities(identities: string[]): void {
    this.identities = identities;
  }

  /**
   * Set recipients for encryption
   */
  setRecipients(recipients: string[]): void {
    this.recipients = recipients;
  }

  /**
   * Add an identity for decryption
   */
  addIdentity(identity: string): void {
    if (!this.identities.includes(identity)) {
      this.identities.push(identity);
    }
  }

  /**
   * Add a recipient for encryption
   */
  addRecipient(recipient: string): void {
    if (!this.recipients.includes(recipient)) {
      this.recipients.push(recipient);
    }
  }

  /**
   * Generate a new age identity
   */
  async generateIdentity(): Promise<string> {
    const identity = await age.generateIdentity();
    return identity;
  }

  /**
   * Convert an identity to a recipient
   */
  async identityToRecipient(identity: string): Promise<string> {
    // Handle SE identities with the Secure Enclave backend
    if (identity.startsWith('AGE-PLUGIN-SE-')) {
      if (!this.secureEnclave) {
        throw new Error('Secure Enclave backend not available for SE identity');
      }
      return await this.secureEnclave.identityToRecipient(identity);
    }
    
    // Handle standard age identities with age-encryption library
    const recipient = await age.identityToRecipient(identity);
    return recipient;
  }

  /**
   * Encrypt data using age encryption with native SE support
   */
  async encrypt(data: string, recipients?: string[]): Promise<Uint8Array> {
    const recipientsToUse = recipients || this.recipients;
    
    if (!recipientsToUse || recipientsToUse.length === 0) {
      throw new Error('No recipients specified for encryption');
    }
    
    // Check if we have SE recipients and can use native SE
    const hasSeRecipients = recipientsToUse.some(r => r.startsWith('age1se1'));
    const hasOtherPluginRecipients = recipientsToUse.some(r => 
      r.startsWith('age1yubikey1') || r.startsWith('age1p256tag1')
    );
    
    // Use native SE encryption if available and we have SE recipients
    if (this.secureEnclave && hasSeRecipients && !hasOtherPluginRecipients && !this.config.useAgeBinary) {
      try {
        // For SE-only encryption, use native SE implementation
        const seRecipients = recipientsToUse.filter(r => r.startsWith('age1se1'));
        const standardRecipients = recipientsToUse.filter(r => !r.startsWith('age1se1'));
        
        if (seRecipients.length > 0 && standardRecipients.length === 0) {
          // Pure SE encryption - use native SE
          const dataBuffer = new TextEncoder().encode(data);
          const encrypted = await this.secureEnclave.encrypt(dataBuffer, seRecipients[0]);
          return encrypted;
        }
      } catch (error) {
        // Fall back to CLI on error
        console.warn('SE native encryption failed, falling back to CLI:', error);
      }
    }
    
    // Only use CLI when explicitly configured or when we don't have SE support
    if (this.config.useAgeBinary) {
      // Use command-line age when explicitly configured
      return await this.encryptWithCLI(data, recipientsToUse);
    }
    
    // Check if we have plugin recipients but no native SE support
    const hasPluginRecipients = recipientsToUse.some(r => 
      r.startsWith('age1se1') || r.startsWith('age1yubikey1')
    );
    
    // Only fall back to CLI if we don't have native SE support AND we have plugin recipients
    if (!this.secureEnclave && hasPluginRecipients) {
      // Use command-line age for plugin support when native SE is not available
      return await this.encryptWithCLI(data, recipientsToUse);
    }
    
    // Use TypeScript age-encryption library for standard recipients
    const encrypter = new age.Encrypter();
    
    for (const recipient of recipientsToUse) {
      encrypter.addRecipient(recipient);
    }

    return await encrypter.encrypt(data);
  }

  /**
   * Encrypt data with a passphrase
   */
  async encryptWithPassphrase(data: string, passphrase: string): Promise<Uint8Array> {
    const encrypter = new age.Encrypter();
    encrypter.setPassphrase(passphrase);
    return await encrypter.encrypt(data);
  }

  /**
   * Decrypt data using age decryption with native SE support
   */
  async decrypt(ciphertext: Uint8Array, identities?: string[]): Promise<string> {
    const identitiesToUse = identities || this.identities;
    
    if (!identitiesToUse || identitiesToUse.length === 0) {
      throw new Error('No identities specified for decryption');
    }
    
    // Check if we have SE identities and can use native SE
    const hasSeIdentities = identitiesToUse.some(i => i.includes('AGE-PLUGIN-SE-'));
    const hasOtherPluginIdentities = identitiesToUse.some(i => i.includes('AGE-PLUGIN-YUBIKEY-'));
    
    // Helper function to check if an identity is our JSON format
    const isJsonFormatIdentity = (identity: string): boolean => {
      if (!identity.startsWith('AGE-PLUGIN-SE-')) return false;
      const base64Data = identity.substring('AGE-PLUGIN-SE-'.length);
      try {
        const decoded = Buffer.from(base64Data, 'base64').toString();
        const keyData = JSON.parse(decoded);
        return !!(keyData.privateKey && keyData.publicKey);
      } catch {
        return false;
      }
    };
    
    // Check if we have JSON format identities (these can't use CLI)
    const hasJsonFormatIdentities = identitiesToUse.some(isJsonFormatIdentity);
    
    // Use native SE decryption if available and we have SE identities
    if (this.secureEnclave && hasSeIdentities && !hasOtherPluginIdentities && !this.config.useAgeBinary) {
      try {
        // For SE-only decryption, use native SE implementation
        const seIdentities = identitiesToUse.filter(i => i.includes('AGE-PLUGIN-SE-'));
        const standardIdentities = identitiesToUse.filter(i => !i.includes('AGE-PLUGIN-SE-'));
        
        if (seIdentities.length > 0 && standardIdentities.length === 0) {
          // Pure SE decryption - use native SE
          // First, try to get the private key reference from the identity
          const keyPair = await this.secureEnclave.loadKeyPair(seIdentities[0]);
          const decrypted = await this.secureEnclave.decrypt(ciphertext, keyPair.privateKeyRef);
          return new TextDecoder().decode(decrypted);
        }
      } catch (error) {
        // For JSON format identities, don't fall back to CLI since they're incompatible
        if (hasJsonFormatIdentities) {
          throw new Error(`Native SE decryption failed: ${error instanceof Error ? error.message : String(error)}. JSON format identities cannot use CLI fallback.`);
        }
        // Fall back to CLI on error (only for CLI-compatible identities)
        console.log('SE native decryption failed, falling back to CLI (CLI-generated identities cannot be used by pure JS implementation)');
      }
    }
    
    // Only use CLI when explicitly configured or when we don't have SE support
    if (this.config.useAgeBinary) {
      // Don't use CLI for JSON format identities (they're incompatible)
      if (hasJsonFormatIdentities) {
        throw new Error('CLI age binary cannot handle JSON format identities. Please use native SE backend or disable useAgeBinary.');
      }
      // Use command-line age when explicitly configured
      return await this.decryptWithCLI(ciphertext, identitiesToUse);
    }
    
    // Check if we have plugin identities but no native SE support
    const hasPluginIdentities = identitiesToUse.some(i => 
      i.includes('AGE-PLUGIN-SE-') || i.includes('AGE-PLUGIN-YUBIKEY-')
    );
    
    // Check if the ciphertext contains plugin-specific headers (for backwards compatibility)
    const ciphertextString = new TextDecoder().decode(ciphertext.slice(0, 200));
    const hasPluginCiphertext = ciphertextString.includes('piv-p256') || ciphertextString.includes('yubikey');
    
    // Only fall back to CLI if we don't have native SE support AND we have plugin content
    // BUT avoid CLI for JSON format identities
    if (!this.secureEnclave && (hasPluginIdentities || hasPluginCiphertext)) {
      // Don't use CLI for JSON format identities (they're incompatible)
      if (hasJsonFormatIdentities) {
        throw new Error('Native SE backend not available and JSON format identities cannot use CLI fallback. Please enable native SE backend.');
      }
      // Use command-line age for plugin support when native SE is not available
      return await this.decryptWithCLI(ciphertext, identitiesToUse);
    }
    
    // Use TypeScript age-encryption library for standard identities
    const decrypter = new age.Decrypter();
    
    for (const identity of identitiesToUse) {
      decrypter.addIdentity(identity);
    }

    return await decrypter.decrypt(ciphertext, "text");
  }

  /**
   * Decrypt data with a passphrase
   */
  async decryptWithPassphrase(ciphertext: Uint8Array, passphrase: string): Promise<string> {
    const decrypter = new age.Decrypter();
    decrypter.addPassphrase(passphrase);
    return await decrypter.decrypt(ciphertext, "text");
  }

  /**
   * Encrypt a file
   */
  async encryptFile(inputPath: string, outputPath: string, recipients?: string[]): Promise<void> {
    const data = fs.readFileSync(inputPath, 'utf8');
    const ciphertext = await this.encrypt(data, recipients);
    fs.writeFileSync(outputPath, ciphertext);
  }

  /**
   * Decrypt a file
   */
  async decryptFile(inputPath: string, outputPath: string, identities?: string[]): Promise<void> {
    const ciphertext = fs.readFileSync(inputPath);
    const plaintext = await this.decrypt(ciphertext, identities);
    fs.writeFileSync(outputPath, plaintext, 'utf8');
  }

  /**
   * Decrypt a file by path using age decryption
   */
  async decryptByPath(filePath: string, identities?: string[]): Promise<string> {
    const identitiesToUse = identities || this.identities;
    
    if (!identitiesToUse || identitiesToUse.length === 0) {
      throw new Error('No identities specified for decryption');
    }
    
    // Check if we have SE identities and can use native SE
    const hasSeIdentities = identitiesToUse.some(i => i.includes('AGE-PLUGIN-SE-'));
    const hasOtherPluginIdentities = identitiesToUse.some(i => i.includes('AGE-PLUGIN-YUBIKEY-'));
    
    // Helper function to check if an identity is our JSON format
    const isJsonFormatIdentity = (identity: string): boolean => {
      if (!identity.startsWith('AGE-PLUGIN-SE-')) return false;
      const base64Data = identity.substring('AGE-PLUGIN-SE-'.length);
      try {
        const decoded = Buffer.from(base64Data, 'base64').toString();
        const keyData = JSON.parse(decoded);
        return !!(keyData.privateKey && keyData.publicKey);
      } catch {
        return false;
      }
    };
    
    // Check if we have JSON format identities (these can't use CLI)
    const hasJsonFormatIdentities = identitiesToUse.some(isJsonFormatIdentity);
    
    // Use native SE decryption if available and we have SE identities
    if (this.secureEnclave && hasSeIdentities && !hasOtherPluginIdentities && !this.config.useAgeBinary) {
      try {
        // For SE-only decryption, use native SE implementation
        const seIdentities = identitiesToUse.filter(i => i.includes('AGE-PLUGIN-SE-'));
        const standardIdentities = identitiesToUse.filter(i => !i.includes('AGE-PLUGIN-SE-'));
        
        if (seIdentities.length > 0 && standardIdentities.length === 0) {
          // Pure SE decryption - use native SE - read file and decrypt
          const fs = await import('fs');
          const ciphertext = fs.readFileSync(filePath);
          const keyPair = await this.secureEnclave.loadKeyPair(seIdentities[0]);
          const decrypted = await this.secureEnclave.decrypt(ciphertext, keyPair.privateKeyRef);
          return new TextDecoder().decode(decrypted);
        }
      } catch (error) {
        // For JSON format identities, don't fall back to CLI since they're incompatible
        if (hasJsonFormatIdentities) {
          throw new Error(`Native SE decryption failed: ${error instanceof Error ? error.message : String(error)}. JSON format identities cannot use CLI fallback.`);
        }
        // Fall back to CLI on error (only for CLI-compatible identities)
        console.log('SE native decryption failed, falling back to CLI (CLI-generated identities cannot be used by pure JS implementation)');
      }
    }
    
    // Only use CLI when explicitly configured or when we don't have SE support
    if (this.config.useAgeBinary) {
      // Don't use CLI for JSON format identities (they're incompatible)
      if (hasJsonFormatIdentities) {
        throw new Error('CLI age binary cannot handle JSON format identities. Please use native SE backend or disable useAgeBinary.');
      }
      // Use command-line age when explicitly configured
      return await this.decryptFileWithCLI(filePath, identitiesToUse);
    }
    
    // Check if we have plugin identities that need CLI support
    const hasPluginIdentities = identitiesToUse.some(i => 
      i.includes('AGE-PLUGIN-SE-') || i.includes('AGE-PLUGIN-YUBIKEY-')
    );
    
    // Fall back to CLI for plugin identities (either no native SE or native SE failed)
    // BUT avoid CLI for JSON format identities
    if (hasPluginIdentities) {
      // Don't use CLI for JSON format identities (they're incompatible)
      if (hasJsonFormatIdentities) {
        throw new Error('Native SE backend not available and JSON format identities cannot use CLI fallback. Please enable native SE backend.');
      }
      // Use command-line age for plugin support
      return await this.decryptFileWithCLI(filePath, identitiesToUse);
    }
    
    // For non-plugin identities, read file and use TypeScript library
    const fs = await import('fs');
    const ciphertext = fs.readFileSync(filePath);
    return await this.decrypt(ciphertext, identitiesToUse);
  }

  /**
   * Encode binary data to ASCII armored format
   */
  encodeArmor(data: Uint8Array): string {
    return age.armor.encode(data);
  }

  /**
   * Decode ASCII armored data to binary
   */
  decodeArmor(armoredData: string): Uint8Array {
    return age.armor.decode(armoredData);
  }

  /**
   * Create WebAuthn credential for hardware security keys
   */
  async createWebAuthnCredential(keyName: string, type: 'passkey' | 'security-key' = 'passkey'): Promise<string | void> {
    if (typeof window === 'undefined') {
      throw new Error('WebAuthn is only available in browser environments');
    }

    if (type === 'security-key') {
      // For security keys, we need to store the identity string
      const identity = await age.webauthn.createCredential({
        type: "security-key",
        keyName: keyName
      });
      return identity;
    } else {
      // For passkeys, no identity string is returned
      await age.webauthn.createCredential({ keyName: keyName });
    }
  }

  /**
   * Encrypt with WebAuthn (passkey)
   */
  async encryptWithWebAuthn(data: string): Promise<Uint8Array> {
    if (typeof window === 'undefined') {
      throw new Error('WebAuthn is only available in browser environments');
    }

    const encrypter = new age.Encrypter();
    encrypter.addRecipient(new age.webauthn.WebAuthnRecipient());
    return await encrypter.encrypt(data);
  }

  /**
   * Decrypt with WebAuthn (passkey)
   */
  async decryptWithWebAuthn(ciphertext: Uint8Array): Promise<string> {
    if (typeof window === 'undefined') {
      throw new Error('WebAuthn is only available in browser environments');
    }

    const decrypter = new age.Decrypter();
    decrypter.addIdentity(new age.webauthn.WebAuthnIdentity());
    return await decrypter.decrypt(ciphertext, "text");
  }

  /**
   * Encrypt with WebAuthn security key using identity
   */
  async encryptWithSecurityKey(data: string, identity: string): Promise<Uint8Array> {
    if (typeof window === 'undefined') {
      throw new Error('WebAuthn is only available in browser environments');
    }

    const encrypter = new age.Encrypter();
    encrypter.addRecipient(new age.webauthn.WebAuthnRecipient({ identity: identity }));
    return await encrypter.encrypt(data);
  }

  /**
   * Decrypt with WebAuthn security key using identity
   */
  async decryptWithSecurityKey(ciphertext: Uint8Array, identity: string): Promise<string> {
    if (typeof window === 'undefined') {
      throw new Error('WebAuthn is only available in browser environments');
    }

    const decrypter = new age.Decrypter();
    decrypter.addIdentity(new age.webauthn.WebAuthnIdentity({ identity: identity }));
    return await decrypter.decrypt(ciphertext, "text");
  }

  /**
   * Use Web Crypto X25519 key as identity
   */
  async useWebCryptoKey(keyPair: CryptoKeyPair): Promise<string> {
    if (typeof window === 'undefined') {
      throw new Error('Web Crypto is only available in browser environments');
    }

    const identity = keyPair.privateKey;
    const recipient = await age.identityToRecipient(identity);
    return recipient;
  }

  /**
   * Generate X25519 key pair using Web Crypto
   */
  async generateWebCryptoKeyPair(): Promise<CryptoKeyPair> {
    if (typeof window === 'undefined') {
      throw new Error('Web Crypto is only available in browser environments');
    }

    const keyPair = await crypto.subtle.generateKey(
      { name: "X25519" },
      false, // not extractable for security
      ["deriveBits"]
    );
    return keyPair as CryptoKeyPair;
  }

  /**
   * Load identities from file
   */
  async loadIdentitiesFromFile(filePath: string): Promise<string[]> {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Identity file not found: ${filePath}`);
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const identities = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));

    return identities;
  }

  /**
   * Save identities to file
   */
  async saveIdentitiesToFile(identities: string[], filePath: string): Promise<void> {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const content = identities.join('\n') + '\n';
    fs.writeFileSync(filePath, content, { mode: 0o600 }); // Restrict permissions
  }

  /**
   * Load recipients from file
   */
  async loadRecipientsFromFile(filePath: string): Promise<string[]> {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Recipients file not found: ${filePath}`);
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const recipients = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));

    return recipients;
  }

  /**
   * Save recipients to file
   */
  async saveRecipientsToFile(recipients: string[], filePath: string): Promise<void> {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const content = recipients.join('\n') + '\n';
    fs.writeFileSync(filePath, content);
  }

  /**
   * Validate identity format
   */
  validateIdentity(identity: string): boolean {
    // Age identities start with AGE-SECRET-KEY-
    return identity.startsWith('AGE-SECRET-KEY-') || 
           identity.startsWith('AGE-PLUGIN-');
  }

  /**
   * Validate recipient format
   */
  validateRecipient(recipient: string): boolean {
    // Age recipients start with age1
    return recipient.startsWith('age1') || 
           recipient.startsWith('age-plugin-');
  }

  /**
   * Check if age-plugin-se is available
   */
  async isSecureEnclaveAvailable(): Promise<boolean> {
    // Use native SE if available, fallback to CLI check
    if (this.secureEnclave) {
      return await this.secureEnclave.isAvailable();
    }
    
    try {
      const { execSync } = await import('child_process');
      execSync('command -v age-plugin-se', { stdio: 'ignore' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Generate a new Secure Enclave identity
   */
  async generateSecureEnclaveIdentity(
    accessControl: string = 'any-biometry-or-passcode',
    outputFile?: string,
    format: 'json' | 'bech32' = 'json'
  ): Promise<string> {
    if (!this.secureEnclave) {
      throw new Error('Secure Enclave not available');
    }

    if (!this.secureEnclave.validateAccessControl(accessControl)) {
      throw new Error(`Invalid access control: ${accessControl}`);
    }

    try {
      const keyPair = await this.secureEnclave.generateKeyPair(accessControl, format);
      
      if (outputFile) {
        const fs = await import('fs');
        const content = [
          `# created: ${new Date().toISOString()}`,
          `# access control: ${accessControl}`,
          `# format: ${format}`,
          `# public key: ${keyPair.recipient}`,
          keyPair.identity
        ].join('\n');
        
        fs.writeFileSync(outputFile, content, { mode: 0o600 });
      }

      return keyPair.identity;
    } catch (error) {
      throw new Error(`Failed to generate Secure Enclave identity: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get recipients from a Secure Enclave identity file
   */
  async getSecureEnclaveRecipients(identityFile: string): Promise<string[]> {
    // Use native SE if available, fallback to CLI
    if (this.secureEnclave) {
      try {
        const content = fs.readFileSync(identityFile, 'utf8');
        const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));
        
        if (lines.length > 0) {
          const identity = lines[0];
          const recipient = await this.secureEnclave.identityToRecipient(identity);
          return [recipient];
        }
      } catch (error) {
        console.warn('Native SE recipient extraction failed, falling back to CLI:', error);
      }
    }
    
    const { execSync } = await import('child_process');
    
    try {
      const result = execSync(`age-plugin-se recipients -i "${identityFile}"`, { 
        encoding: 'utf8',
        env: { ...process.env, PATH: '/opt/homebrew/bin:/usr/local/bin:' + process.env.PATH }
      });
      
      // Clean up the output - remove any trailing % or whitespace and split by lines
      return result
        .replace(/%$/, '') // Remove trailing %
        .trim()
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && line.startsWith('age1se1'));
    } catch (error) {
      throw new Error(`Failed to get Secure Enclave recipients: ${error}`);
    }
  }

  /**
   * Convert age-plugin-se recipient to age-plugin-yubikey recipient
   */
  convertSecureEnclaveToYubikey(recipient: string): string {
    if (!recipient.startsWith('age1se1')) {
      throw new Error('Invalid Secure Enclave recipient format');
    }
    
    // Extract the data portion (after 'age1se1q')
    const dataWithoutPrefix = recipient.substring(7); // Remove 'age1se1q'
    
    // Convert to YubiKey format
    return `age1yubikey1q${dataWithoutPrefix}`;
  }

  /**
   * Convert age-plugin-yubikey recipient to age-plugin-se recipient
   */
  convertYubikeyToSecureEnclave(recipient: string): string {
    if (!recipient.startsWith('age1yubikey1')) {
      throw new Error('Invalid YubiKey recipient format');
    }
    
    // Extract the data portion (after 'age1yubikey1q')
    const dataWithoutPrefix = recipient.substring(12); // Remove 'age1yubikey1q'
    
    // Convert to Secure Enclave format
    return `age1se1q${dataWithoutPrefix}`;
  }

  /**
   * Validate Secure Enclave access control option
   */
  validateAccessControl(accessControl: string): boolean {
    const validOptions = [
      'none',
      'passcode',
      'any-biometry',
      'any-biometry-and-passcode',
      'any-biometry-or-passcode',
      'current-biometry',
      'current-biometry-and-passcode'
    ];
    
    return validOptions.includes(accessControl);
  }

  /**
   * Check if the current macOS version supports Secure Enclave
   */
  async checkSecureEnclaveSupport(): Promise<{ supported: boolean; version?: string; message?: string }> {
    const { execSync } = await import('child_process');
    const os = await import('os');
    
    if (os.platform() !== 'darwin') {
      return {
        supported: false,
        message: 'Secure Enclave is only available on macOS'
      };
    }
    
    try {
      const swVers = execSync('sw_vers -productVersion', { encoding: 'utf8' }).trim();
      const version = swVers.split('.').map(Number);
      
      // Secure Enclave support requires macOS 13.0 (Ventura) or later
      const isSupported = version[0] >= 13;
      
      return {
        supported: isSupported,
        version: swVers,
        message: isSupported 
          ? `Secure Enclave supported on macOS ${swVers}`
          : `Secure Enclave requires macOS 13.0 (Ventura) or later, found ${swVers}`
      };
    } catch (error) {
      return {
        supported: false,
        message: 'Could not determine macOS version'
      };
    }
  }

  /**
   * Get detailed information about Secure Enclave availability
   */
  async getSecureEnclaveInfo(): Promise<{
    available: boolean;
    plugin: boolean;
    platform: boolean;
    version?: string;
    message: string;
  }> {
    const pluginAvailable = await this.isSecureEnclaveAvailable();
    const platformSupport = await this.checkSecureEnclaveSupport();
    
    return {
      available: pluginAvailable && platformSupport.supported,
      plugin: pluginAvailable,
      platform: platformSupport.supported,
      ...(platformSupport.version && { version: platformSupport.version }),
      message: !pluginAvailable 
        ? 'age-plugin-se not installed. Install with: brew install age-plugin-se'
        : !platformSupport.supported 
        ? platformSupport.message!
        : 'Secure Enclave fully supported'
    };
  }

  /**
   * Encrypt data using command-line age (for plugin support)
   */
  private async encryptWithCLI(data: string, recipients: string[]): Promise<Uint8Array> {
    const { execSync } = await import('child_process');
    const { writeFileSync, readFileSync, unlinkSync } = await import('fs');
    const { join } = await import('path');
    const { tmpdir } = await import('os');
    
    const tmpInput = join(tmpdir(), `age-input-${Date.now()}.txt`);
    const tmpOutput = join(tmpdir(), `age-output-${Date.now()}.age`);
    
    try {
      // Write input data to temporary file
      writeFileSync(tmpInput, data, 'utf8');
      
      // Get age binary path - ensure it's in the PATH
      let ageBinary = this.config.ageBinaryPath || 'age';
      
      // If no custom path is set, try to find the age binary in common locations
      if (!this.config.ageBinaryPath) {
        try {
          const { execSync: execSyncForPath } = await import('child_process');
          const whichResult = execSyncForPath('which age', { 
            encoding: 'utf8',
            env: { 
              ...process.env, 
              PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || '')
            }
          }).trim();
          ageBinary = whichResult;
        } catch {
          // Fall back to just 'age' if which fails
          ageBinary = 'age';
        }
      }
      
      // Build age command with recipients
      const recipientArgs = recipients.map(r => `-r "${r}"`).join(' ');
      const command = `"${ageBinary}" ${recipientArgs} -o "${tmpOutput}" "${tmpInput}"`;
      
      // Set up environment with proper PATH for age plugins
      const env = {
        ...process.env,
        PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || ''),
        // Ensure age can find plugins
        AGE_PLUGIN_PATH: '/opt/homebrew/bin:/usr/local/bin'
      };
      
      // Execute age command with proper environment
      execSync(command, { 
        stdio: 'pipe',
        env: env
      });
      
      // Read encrypted output
      const encryptedData = readFileSync(tmpOutput);
      
      return new Uint8Array(encryptedData);
    } catch (error) {
      throw new Error(`Age CLI encryption failed: ${error}`);
    } finally {
      // Clean up temporary files
      try {
        unlinkSync(tmpInput);
        unlinkSync(tmpOutput);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Decrypt data using command-line age (for plugin support)
   */
  private async decryptWithCLI(ciphertext: Uint8Array, identities: string[]): Promise<string> {
    const { execSync } = await import('child_process');
    const { writeFileSync, readFileSync, unlinkSync } = await import('fs');
    const { join } = await import('path');
    const { tmpdir } = await import('os');
    
    const tmpInput = join(tmpdir(), `age-input-${Date.now()}.age`);
    const tmpOutput = join(tmpdir(), `age-output-${Date.now()}.txt`);
    const tmpIdentities = join(tmpdir(), `age-identities-${Date.now()}.txt`);
    
    try {
      // Write ciphertext to temporary file
      writeFileSync(tmpInput, ciphertext);
      
      // Write identities to temporary file
      writeFileSync(tmpIdentities, identities.join('\n'), 'utf8');
      
      // Get age binary path - ensure it's in the PATH
      let ageBinary = this.config.ageBinaryPath || 'age';
      
      // If no custom path is set, try to find the age binary in common locations
      if (!this.config.ageBinaryPath) {
        try {
          const { execSync: execSyncForPath } = await import('child_process');
          const whichResult = execSyncForPath('which age', { 
            encoding: 'utf8',
            env: { 
              ...process.env, 
              PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || '')
            }
          }).trim();
          ageBinary = whichResult;
        } catch {
          // Fall back to just 'age' if which fails
          ageBinary = 'age';
        }
      }
      
      // Build age command
      const command = `"${ageBinary}" --decrypt -i "${tmpIdentities}" -o "${tmpOutput}" "${tmpInput}"`;
      
      // Set up environment with proper PATH for age plugins
      const env = {
        ...process.env,
        PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || ''),
        // Ensure age can find plugins
        AGE_PLUGIN_PATH: '/opt/homebrew/bin:/usr/local/bin'
      };
      
      // Execute age command with stdio: 'inherit' to allow Touch ID prompt
      execSync(command, { 
        stdio: 'inherit',
        env: env
      });
      
      // Read decrypted output
      const decryptedData = readFileSync(tmpOutput, 'utf8');
      
      return decryptedData;
    } catch (error) {
      throw new Error(`Age CLI decryption failed: ${error}`);
    } finally {
      // Clean up temporary files
      try {
        unlinkSync(tmpInput);
        unlinkSync(tmpOutput);
        unlinkSync(tmpIdentities);
      } catch {
        // Ignore cleanup errors
      }
    }
  }

  /**
   * Decrypt a file using command-line age (for plugin support)
   */
  private async decryptFileWithCLI(filePath: string, identities: string[]): Promise<string> {
    const { execSync } = await import('child_process');
    const { writeFileSync, readFileSync, unlinkSync } = await import('fs');
    const { join } = await import('path');
    const { tmpdir } = await import('os');
    
    const tmpOutput = join(tmpdir(), `age-output-${Date.now()}.txt`);
    const tmpIdentities = join(tmpdir(), `age-identities-${Date.now()}.txt`);
    
    try {
      // Write identities to temporary file
      writeFileSync(tmpIdentities, identities.join('\n'), 'utf8');
      
      // Get age binary path - ensure it's in the PATH
      let ageBinary = this.config.ageBinaryPath || 'age';
      
      // If no custom path is set, try to find the age binary in common locations
      if (!this.config.ageBinaryPath) {
        try {
          const { execSync: execSyncForPath } = await import('child_process');
          const whichResult = execSyncForPath('which age', { 
            encoding: 'utf8',
            env: { 
              ...process.env, 
              PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || '')
            }
          }).trim();
          ageBinary = whichResult;
        } catch {
          // Fall back to just 'age' if which fails
          ageBinary = 'age';
        }
      }
      
      // Build age command
      const command = `"${ageBinary}" --decrypt -i "${tmpIdentities}" -o "${tmpOutput}" "${filePath}"`;
      
      // Set up environment with proper PATH for age plugins
      const env = {
        ...process.env,
        PATH: '/opt/homebrew/bin:/usr/local/bin:' + (process.env.PATH || ''),
        // Ensure age can find plugins
        AGE_PLUGIN_PATH: '/opt/homebrew/bin:/usr/local/bin'
      };
      
      // Execute age command with stdio: 'inherit' to allow Touch ID prompt
      execSync(command, { 
        stdio: 'inherit',
        env: env
      });
      
      // Read decrypted output
      const decryptedData = readFileSync(tmpOutput, 'utf8');
      
      return decryptedData;
    } catch (error) {
      throw new Error(`Age CLI decryption failed: ${error}`);
    } finally {
      // Clean up temporary files
      try {
        unlinkSync(tmpOutput);
        unlinkSync(tmpIdentities);
      } catch {
        // Ignore cleanup errors
      }
    }
  }
}
