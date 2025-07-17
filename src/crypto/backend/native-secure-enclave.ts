/**
 * Native Apple Secure Enclave Helper
 *
 * This class is no longer a full backend. Its sole responsibility is to act as a
 * performance-enhancing helper for the SecureEnclaveManager on macOS. It uses the
 * native Swift addon to accelerate specific, non-cryptographic operations that
 * would otherwise require slower CLI calls.
 */

import * as path from 'path';
import {
  SecureEnclaveConfig,
} from '../../types';
import {
  encodeRecipient,
  decodeIdentity,
  compressPublicKey,
} from '../format-utils';

// Load the native addon
let nativeAddon: any;
try {
  const nativeModulePath = path.join(__dirname, '../../../native');
  nativeAddon = require(nativeModulePath);
} catch (error) {
  nativeAddon = null; // Gracefully handle missing addon
}

export class NativeSecureEnclave {
  constructor(_config: SecureEnclaveConfig) {
    if (!nativeAddon) {
      throw new Error('Native Secure Enclave addon not available. Please build the native module first.');
    }
  }

  /**
   * Checks if the native addon is loaded and functional.
   */
  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin' || !nativeAddon) {
      return false;
    }
    try {
      return nativeAddon.isAvailable();
    } catch (error) {
      return false;
    }
  }

  /**
   * Uses the high-performance native addon to convert a standard,
   * CLI-compatible identity into its corresponding recipient.
   * This avoids a slower `child_process` call.
   *
   * @param identity The CLI-compatible AGE-PLUGIN-SE- identity string.
   * @returns The corresponding age1se1 recipient string.
   */
  async identityToRecipient(identity: string): Promise<string> {
    // The native addon needs the raw private key data from the identity.
    const privateKeyData = decodeIdentity(identity);

    // The native addon's getPublicKey function will derive the public key
    // from the private key data representation.
    const rawPublicKey = await nativeAddon.getPublicKey(privateKeyData);
    if (!rawPublicKey) {
        throw new Error('Failed to get public key from native addon.');
    }

    const compressedPubKey = compressPublicKey(rawPublicKey);
    return encodeRecipient(compressedPubKey);
  }
}