/**
 * Apple Secure Enclave Example
 * Demonstrates how to use Apple SE for age encryption
 */

const { AgeManager } = require('../dist/crypto/age-manager');

async function demonstrateSecureEnclave() {
  console.log('Apple Secure Enclave Integration Example');
  console.log('=======================================');

  // Create an age manager with SE support
  const ageManager = new AgeManager();

  try {
    // Check if SE is available
    const isAvailable = await ageManager.isSecureEnclaveAvailable();
    if (!isAvailable) {
      console.log('⚠️  Apple Secure Enclave is not available on this device');
      console.log('Requirements:');
      console.log('- macOS 13.0 (Ventura) or later');
      console.log('- Device with Apple T2 chip or Apple Silicon');
      return;
    }

    console.log('✅ Apple Secure Enclave is available');

    // Get SE capabilities
    const seInfo = await ageManager.getSecureEnclaveInfo();
    console.log('SE Info:', seInfo);

    // Generate a new SE identity
    console.log('\n🔐 Generating new Secure Enclave identity...');
    const identity = await ageManager.generateSecureEnclaveIdentity('any-biometry-or-passcode');
    console.log('Generated identity:', identity.substring(0, 50) + '...');

    // Convert identity to recipient
    const recipient = await ageManager.identityToRecipient(identity);
    console.log('Recipient:', recipient);

    // Test encryption/decryption
    console.log('\n🔒 Testing encryption/decryption...');
    const testData = 'Hello, Apple Secure Enclave!';
    
    // Set up recipients and identities
    ageManager.setRecipients([recipient]);
    ageManager.setIdentities([identity]);

    // Encrypt data
    const encrypted = await ageManager.encrypt(testData);
    console.log('Encrypted data size:', encrypted.length, 'bytes');

    // Decrypt data
    const decrypted = await ageManager.decrypt(encrypted);
    console.log('Decrypted data:', decrypted);

    if (decrypted === testData) {
      console.log('✅ Encryption/decryption successful!');
    } else {
      console.log('❌ Encryption/decryption failed!');
    }

    // Demonstrate different access control options
    console.log('\n🔐 Testing different access control options...');
    const accessControls = [
      'any-biometry',
      'any-biometry-or-passcode',
      'current-biometry',
      'passcode'
    ];

    for (const accessControl of accessControls) {
      try {
        console.log(`\nTesting ${accessControl}:`);
        const seIdentity = await ageManager.generateSecureEnclaveIdentity(accessControl);
        const seRecipient = await ageManager.identityToRecipient(seIdentity);
        console.log(`✅ ${accessControl}: ${seRecipient.substring(0, 20)}...`);
      } catch (error) {
        console.log(`❌ ${accessControl}: ${error.message}`);
      }
    }

  } catch (error) {
    console.error('Error:', error.message);
  }
}

if (require.main === module) {
  demonstrateSecureEnclave().catch(console.error);
}

module.exports = {
  demonstrateSecureEnclave,
};