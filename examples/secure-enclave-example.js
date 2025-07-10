/**
 * Apple Secure Enclave Example
 * Demonstrates how to use Apple SE for age encryption
 */

const { AgeManager } = require('../dist/crypto/age-manager');
const { AppleSecureEnclave } = require('../dist/crypto/apple-secure-enclave');

async function demonstrateSecureEnclave() {
  console.log('Apple Secure Enclave Integration Example');
  console.log('=======================================');

  // Create an age manager with SE support
  const config = {
    useAgeBinary: false,  // Use native SE integration
    seAccessControl: 'any-biometry-or-passcode',
    seAutoConfirm: false
  };

  const ageManager = new AgeManager(config);

  try {
    // Check if SE is available
    const isAvailable = await ageManager.isSecureEnclaveAvailable();
    if (!isAvailable) {
      console.log('⚠️  Apple Secure Enclave is not available on this device');
      console.log('Requirements:');
      console.log('- macOS 13.0 (Ventura) or later');
      console.log('- Device with Apple T2 chip or Apple Silicon');
      console.log('- age-plugin-se installed');
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

// Direct SE module example
async function directSecureEnclaveExample() {
  console.log('\n🔧 Direct Secure Enclave Module Example');
  console.log('=====================================');

  const seConfig = {
    accessControl: 'any-biometry-or-passcode',
    recipientType: 'piv-p256',
    useNative: true
  };

  const secureEnclave = new AppleSecureEnclave(seConfig);

  try {
    // Check availability
    const isAvailable = await secureEnclave.isAvailable();
    if (!isAvailable) {
      console.log('⚠️  SE module not available');
      return;
    }

    // Get capabilities
    const capabilities = await secureEnclave.getCapabilities();
    console.log('SE Capabilities:', capabilities);

    // Generate key pair
    console.log('\n🔑 Generating SE key pair...');
    const keyPair = await secureEnclave.generateKeyPair('any-biometry-or-passcode');
    console.log('Key pair generated:');
    console.log('- Identity:', keyPair.identity.substring(0, 50) + '...');
    console.log('- Recipient:', keyPair.recipient);
    console.log('- Access Control:', keyPair.accessControl);
    console.log('- Created:', keyPair.createdAt);

    // Test identity to recipient conversion
    const convertedRecipient = await secureEnclave.identityToRecipient(keyPair.identity);
    console.log('Converted recipient:', convertedRecipient);

    if (convertedRecipient === keyPair.recipient) {
      console.log('✅ Identity to recipient conversion successful!');
    } else {
      console.log('❌ Identity to recipient conversion failed!');
    }

  } catch (error) {
    console.error('Direct SE Error:', error.message);
  }
}

// Performance comparison example
async function performanceComparison() {
  console.log('\n⚡ Performance Comparison: Native SE vs CLI');
  console.log('==========================================');

  const nativeConfig = {
    useAgeBinary: false,
    seAccessControl: 'any-biometry-or-passcode'
  };

  const cliConfig = {
    useAgeBinary: true,
    seAccessControl: 'any-biometry-or-passcode'
  };

  const nativeManager = new AgeManager(nativeConfig);
  const cliManager = new AgeManager(cliConfig);

  try {
    // Generate identity with native SE
    console.log('🔄 Generating identity with native SE...');
    const start1 = Date.now();
    const nativeIdentity = await nativeManager.generateSecureEnclaveIdentity();
    const nativeTime = Date.now() - start1;
    console.log(`Native SE: ${nativeTime}ms`);

    // Generate identity with CLI
    console.log('🔄 Generating identity with CLI...');
    const start2 = Date.now();
    const cliIdentity = await cliManager.generateSecureEnclaveIdentity();
    const cliTime = Date.now() - start2;
    console.log(`CLI: ${cliTime}ms`);

    console.log(`\n⚡ Performance improvement: ${((cliTime - nativeTime) / cliTime * 100).toFixed(1)}%`);

  } catch (error) {
    console.error('Performance comparison error:', error.message);
  }
}

// Run all examples
async function runAllExamples() {
  await demonstrateSecureEnclave();
  await directSecureEnclaveExample();
  await performanceComparison();
}

if (require.main === module) {
  runAllExamples().catch(console.error);
}

module.exports = {
  demonstrateSecureEnclave,
  directSecureEnclaveExample,
  performanceComparison
}; 