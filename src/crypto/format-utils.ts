/**
 * Cryptographic Format Utilities
 * 
 * This module provides a centralized set of functions for encoding, decoding,
 * and handling cryptographic key formats in a standardized way, compatible
 * with the age-plugin-se specification. It uses 'bech32' for encoding and
 * '@noble/curves' for elliptic curve operations to ensure consistency across
 * all backends (CLI, Pure JS, Native).
 */

import { bech32 } from 'bech32';
import { p256 } from '@noble/curves/p256';

const IDENTITY_PREFIX = 'AGE-PLUGIN-SE-';
const IDENTITY_PREFIX_LOWERCASE = 'age-plugin-se-';
const RECIPIENT_PREFIX = 'age1se'; // Use age1se to match age-plugin-se binary

// Debug logging helper
function debugLog(operation: string, data: any) {
    if (process.env.DEBUG_CRYPTO) {
        console.log(`[format-utils] ${operation}:`, data);
    }
}

export function compressPublicKey(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length === 33) return publicKey;
    if (publicKey.length === 64) {
        const uncompressed = new Uint8Array(65);
        uncompressed[0] = 0x04;
        uncompressed.set(publicKey, 1);
        return p256.Point.fromHex(uncompressed).toBytes(true);
    }
    return p256.Point.fromHex(publicKey).toBytes(true);
}

export function decompressPublicKey(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length === 64) return publicKey;
    if (publicKey.length !== 33) throw new Error(`Invalid compressed public key length: ${publicKey.length}`);
    return p256.Point.fromHex(publicKey).toBytes(false).slice(1);
}

export function encodeIdentity(privateKeyData: Uint8Array): string {
    debugLog('encodeIdentity input', {
        length: privateKeyData.length,
        hex: Buffer.from(privateKeyData).toString('hex').substring(0, 32) + '...'
    });
    
    const words = bech32.toWords(privateKeyData);
    
    debugLog('encodeIdentity words', {
        wordsLength: words.length,
        estimatedOutputLength: IDENTITY_PREFIX_LOWERCASE.length + 1 + words.length + 6 // 6 for checksum
    });
    
    // Use lowercase prefix for consistency with our backends
    const result = bech32.encode(IDENTITY_PREFIX_LOWERCASE, words);
    debugLog('encodeIdentity result', { length: result.length, result });
    return result;
}

export function decodeIdentity(identity: string): Uint8Array {
    debugLog('decodeIdentity input', { identity });
    
    // Use original bech32 for age compatibility
    const { prefix, words } = bech32.decode(identity);
    
    // Accept both uppercase and lowercase prefixes
    if (prefix !== IDENTITY_PREFIX && prefix !== IDENTITY_PREFIX_LOWERCASE) {
        throw new Error(`Invalid identity prefix: ${prefix}. Expected ${IDENTITY_PREFIX} or ${IDENTITY_PREFIX_LOWERCASE}`);
    }
    
    const result = new Uint8Array(bech32.fromWords(words));
    
    debugLog('decodeIdentity result', {
        length: result.length,
        hex: Buffer.from(result).toString('hex').substring(0, 32) + '...'
    });
    return result;
}

export function encodeRecipient(publicKey: Uint8Array): string {
    debugLog('encodeRecipient input', {
        length: publicKey.length,
        hex: Buffer.from(publicKey).toString('hex')
    });
    
    if (publicKey.length !== 33) throw new Error(`Invalid public key length for recipient encoding: ${publicKey.length}. Must be 33 bytes (compressed).`);
    
    // Use original bech32 for age compatibility
    const words = bech32.toWords(publicKey);
    const result = bech32.encode(RECIPIENT_PREFIX, words);
    
    debugLog('encodeRecipient result', { result });
    return result;
}

export function decodeRecipient(recipient: string): Uint8Array {
    debugLog('decodeRecipient input', { recipient });
    
    // Use original bech32 for age compatibility
    const { prefix, words } = bech32.decode(recipient);
    
    // Accept age1se prefix
    if (prefix !== RECIPIENT_PREFIX) {
        throw new Error(`Invalid recipient prefix: ${prefix}. Expected ${RECIPIENT_PREFIX}`);
    }
    
    const result = new Uint8Array(bech32.fromWords(words));
    
    debugLog('decodeRecipient result', {
        length: result.length,
        hex: Buffer.from(result).toString('hex')
    });
    return result;
}