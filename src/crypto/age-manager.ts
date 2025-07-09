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

  constructor(_: PakConfig) {
    // We don't need to store the config since we're managing identities/recipients directly
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
    const encrypter = new age.Encrypter();
    
    // Add recipients if provided
    if (recipients && recipients.length > 0) {
      for (const recipient of recipients) {
        encrypter.addRecipient(recipient);
      }
    } else if (this.recipients && this.recipients.length > 0) {
      // Use stored recipients
      for (const recipient of this.recipients) {
        encrypter.addRecipient(recipient);
      }
    } else {
      throw new Error('No recipients specified for encryption');
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
    const decrypter = new age.Decrypter();
    
    // Add identities if provided
    if (identities && identities.length > 0) {
      for (const identity of identities) {
        decrypter.addIdentity(identity);
      }
    } else if (this.identities && this.identities.length > 0) {
      // Use stored identities
      for (const identity of this.identities) {
        decrypter.addIdentity(identity);
      }
    } else {
      throw new Error('No identities specified for decryption');
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
} 