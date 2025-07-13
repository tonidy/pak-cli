const path = require('path');
const fs = require('fs');

// Try to load the native addon
let nativeAddon;

try {
  // First try to load the built addon
  const buildPath = path.join(__dirname, 'build', 'Release', 'secure_enclave_native.node');
  if (fs.existsSync(buildPath)) {
    nativeAddon = require(buildPath);
  } else {
    // Fallback to debug build
    const debugPath = path.join(__dirname, 'build', 'Debug', 'secure_enclave_native.node');
    if (fs.existsSync(debugPath)) {
      nativeAddon = require(debugPath);
    } else {
      throw new Error('Native addon not found. Please run "npm run build" first.');
    }
  }
} catch (error) {
  // If loading fails, we'll throw an error when methods are called
  console.warn('Native Secure Enclave binary not available:', error.message);
  console.warn('This is normal if installed from npm. Use CLI backend instead.');
  nativeAddon = null;
}

function ensureAddonLoaded() {
  if (!nativeAddon) {
    throw new Error('Native Secure Enclave addon not available. This requires macOS with Secure Enclave support.');
  }
}

/**
 * Check if Secure Enclave is available on this device
 * @returns {boolean} True if Secure Enclave is available
 */
function isAvailable() {
  if (!nativeAddon) {
    return false;
  }
  
  try {
    return nativeAddon.isAvailable();
  } catch (error) {
    console.warn('Error checking Secure Enclave availability:', error.message);
    return false;
  }
}

/**
 * Generate a new key pair in the Secure Enclave
 * @param {string} accessControl - Access control policy for the key
 * @returns {Promise<{publicKey: Buffer, privateKey: Buffer}>} The generated key pair
 */
async function generateKeyPair(accessControl = 'any-biometry-or-passcode') {
  ensureAddonLoaded();
  
  return new Promise((resolve, reject) => {
    try {
      const result = nativeAddon.generateKeyPair(accessControl);
      resolve(result);
    } catch (error) {
      reject(new Error(`Failed to generate key pair: ${error.message}`));
    }
  });
}

/**
 * Encrypt data using a public key
 * @param {Buffer} data - The data to encrypt
 * @param {Buffer} publicKey - The public key to use for encryption
 * @returns {Promise<Buffer>} The encrypted data
 */
async function encrypt(data, publicKey) {
  ensureAddonLoaded();
  
  if (!Buffer.isBuffer(data)) {
    throw new Error('Data must be a Buffer');
  }
  
  if (!Buffer.isBuffer(publicKey)) {
    throw new Error('Public key must be a Buffer');
  }
  
  return new Promise((resolve, reject) => {
    try {
      const result = nativeAddon.encrypt(data, publicKey);
      resolve(result);
    } catch (error) {
      reject(new Error(`Failed to encrypt data: ${error.message}`));
    }
  });
}

/**
 * Decrypt data using a private key from the Secure Enclave
 * @param {Buffer} ciphertext - The encrypted data
 * @param {Buffer} privateKey - The private key data from the Secure Enclave
 * @returns {Promise<Buffer>} The decrypted data
 */
async function decrypt(ciphertext, privateKey) {
  ensureAddonLoaded();
  
  if (!Buffer.isBuffer(ciphertext)) {
    throw new Error('Ciphertext must be a Buffer');
  }
  
  if (!Buffer.isBuffer(privateKey)) {
    throw new Error('Private key must be a Buffer');
  }
  
  return new Promise((resolve, reject) => {
    try {
      const result = nativeAddon.decrypt(ciphertext, privateKey);
      resolve(result);
    } catch (error) {
      reject(new Error(`Failed to decrypt data: ${error.message}`));
    }
  });
}

/**
 * Get the public key from private key data
 * @param {Buffer} privateKey - The private key data
 * @returns {Promise<Buffer>} The public key
 */
async function getPublicKey(privateKey) {
  ensureAddonLoaded();
  
  if (!Buffer.isBuffer(privateKey)) {
    throw new Error('Private key must be a Buffer');
  }
  
  return new Promise((resolve, reject) => {
    try {
      const result = nativeAddon.getPublicKey(privateKey);
      resolve(result);
    } catch (error) {
      reject(new Error(`Failed to get public key: ${error.message}`));
    }
  });
}

/**
 * Delete a key from the Secure Enclave
 * @param {Buffer} privateKey - The private key data to delete
 * @returns {Promise<boolean>} True if the key was deleted successfully
 */
async function deleteKey(privateKey) {
  ensureAddonLoaded();
  
  if (!Buffer.isBuffer(privateKey)) {
    throw new Error('Private key must be a Buffer');
  }
  
  return new Promise((resolve, reject) => {
    try {
      const result = nativeAddon.deleteKey(privateKey);
      resolve(result);
    } catch (error) {
      reject(new Error(`Failed to delete key: ${error.message}`));
    }
  });
}

/**
 * Get information about the native addon
 * @returns {object} Information about the addon
 */
function getInfo() {
  return {
    available: isAvailable(),
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.version,
    addonLoaded: nativeAddon !== null
  };
}

/**
 * Test basic CryptoKit operations
 * @returns {boolean} True if basic CryptoKit operations work
 */
function testCryptoKitBasic() {
  ensureAddonLoaded();
  
  try {
    return nativeAddon.testCryptoKitBasic();
  } catch (error) {
    console.warn('Error testing basic CryptoKit operations:', error.message);
    return false;
  }
}

module.exports = {
  isAvailable,
  generateKeyPair,
  encrypt,
  decrypt,
  getPublicKey,
  deleteKey,
  getInfo,
  testCryptoKitBasic
}; 