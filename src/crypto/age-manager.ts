/**
 * Age Encryption Manager
 */

import * as age from 'age-encryption';
import * as fs from 'fs';
import * as path from 'path';
import { PakConfig } from '../types';

export class AgeManager {
  private identities: string[] = [];
  private recipients: string[] = [];
  private config: PakConfig;

  constructor(config: PakConfig) {
    this.config = config;
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
    const recipient = await age.identityToRecipient(identity);
    return recipient;
  }

  /**
   * Encrypt data using age encryption
   */
  async encrypt(data: string, recipients?: string[]): Promise<Uint8Array> {
    const recipientsToUse = recipients || this.recipients;
    
    if (!recipientsToUse || recipientsToUse.length === 0) {
      throw new Error('No recipients specified for encryption');
    }
    
    // Check if binary usage is forced or needed for plugins
    const hasPluginRecipients = recipientsToUse.some(r => 
      r.startsWith('age1se1') || r.startsWith('age1yubikey1')
    );
    
    if (this.config.useAgeBinary || hasPluginRecipients) {
      // Use command-line age for plugin support or when explicitly configured
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
   * Decrypt data using age decryption
   */
  async decrypt(ciphertext: Uint8Array, identities?: string[]): Promise<string> {
    const identitiesToUse = identities || this.identities;
    
    if (!identitiesToUse || identitiesToUse.length === 0) {
      throw new Error('No identities specified for decryption');
    }
    
    // Check if binary usage is forced or needed for plugins
    const hasPluginIdentities = identitiesToUse.some(i => 
      i.includes('AGE-PLUGIN-SE-') || i.includes('AGE-PLUGIN-YUBIKEY-')
    );
    
    // Also check if the ciphertext contains plugin-specific headers
    const ciphertextString = new TextDecoder().decode(ciphertext.slice(0, 200));
    const hasPluginCiphertext = ciphertextString.includes('piv-p256') || ciphertextString.includes('yubikey');
    
    if (this.config.useAgeBinary || hasPluginIdentities || hasPluginCiphertext) {
      // Use command-line age for plugin support or when explicitly configured
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
    
    // Check if binary usage is forced or needed for plugins
    const hasPluginIdentities = identitiesToUse.some(i => 
      i.includes('AGE-PLUGIN-SE-') || i.includes('AGE-PLUGIN-YUBIKEY-')
    );
    
    // For file-based decryption, we should use CLI when we have plugin identities
    // or when explicitly configured to use binary
    if (this.config.useAgeBinary || hasPluginIdentities) {
      // Use command-line age for plugin support or when explicitly configured
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
    outputFile?: string
  ): Promise<string> {
    const { execSync } = await import('child_process');
    
    try {
      const command = outputFile 
        ? `age-plugin-se keygen --access-control="${accessControl}" -o "${outputFile}"`
        : `age-plugin-se keygen --access-control="${accessControl}"`;
      
      const result = execSync(command, { encoding: 'utf8' });
      
      if (outputFile) {
        return result; // Command output with confirmation
      } else {
        return result; // Identity content
      }
    } catch (error) {
      throw new Error(`Failed to generate Secure Enclave identity: ${error}`);
    }
  }

  /**
   * Get recipients from a Secure Enclave identity file
   */
  async getSecureEnclaveRecipients(identityFile: string): Promise<string[]> {
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
