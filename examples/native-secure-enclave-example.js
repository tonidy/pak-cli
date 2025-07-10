#!/usr/bin/env node

/**
 * Native Secure Enclave Example
 * 
 * This example demonstrates how to use the native Swift-based Secure Enclave
 * implementation for secure password management.
 */

const { PasswordManager } = require('../dist/index.js');

async function runExample() {
  console.log('🔒 Native Secure Enclave Example');
  console.log('================================\n');

  try {
    // Create password manager with native Secure Enclave backend
    const pm = new PasswordManager({
      backend: 'native',
      accessControl: 'any-biometry-or-passcode',
      recipientType: 'piv-p256',
      useNative: true
    });

    console.log('📱 Checking Secure Enclave availability...');
    const manager = pm.getSecureEnclaveManager();
    const available = await manager.isAvailable();
    
    if (!available) {
      console.log('❌ Secure Enclave is not available on this device');
      console.log('   Requirements:');
      console.log('   - macOS with Secure Enclave support');
      console.log('   - Native addon built and installed');
      return;
    }

    console.log('✅ Secure Enclave is available');
    
    // Get capabilities
    const capabilities = await manager.getCapabilities();
    console.log('\n📊 Secure Enclave Capabilities:');
    console.log(`   Platform: ${capabilities.platform}`);
    console.log(`   Version: ${capabilities.version}`);
    console.log(`   Supports key generation: ${capabilities.supportsKeyGeneration}`);
    console.log(`   Supports encryption: ${capabilities.supportsEncryption}`);
    console.log(`   Supports decryption: ${capabilities.supportsDecryption}`);
    console.log(`   Supported access controls: ${capabilities.supportedAccessControls.join(', ')}`);

    // Generate a key pair
    console.log('\n🔑 Generating Secure Enclave key pair...');
    const keyPair = await manager.generateKeyPair('any-biometry-or-passcode');
    console.log('✅ Key pair generated successfully');
    console.log(`   Identity: ${keyPair.identity.substring(0, 50)}...`);
    console.log(`   Recipient: ${keyPair.recipient}`);
    console.log(`   Access Control: ${keyPair.accessControl}`);
    console.log(`   Created: ${keyPair.createdAt.toISOString()}`);

    // Initialize the password manager with the key
    console.log('\n🔐 Initializing password manager...');
    await pm.initialize(keyPair.identity);
    console.log('✅ Password manager initialized');

    // Add some test passwords
    console.log('\n📝 Adding test passwords...');
    
    await pm.addPassword('github.com', 'my-username', 'super-secret-password-123');
    console.log('✅ Added GitHub credentials');
    
    await pm.addPassword('example.com', 'user@example.com', 'another-secure-password');
    console.log('✅ Added example.com credentials');
    
    await pm.addPassword('work-vpn', 'employee-id', 'vpn-password-456');
    console.log('✅ Added work VPN credentials');

    // List all passwords
    console.log('\n📋 Listing all stored passwords...');
    const passwords = await pm.listPasswords();
    console.log(`Found ${passwords.length} stored passwords:`);
    passwords.forEach((entry, index) => {
      console.log(`   ${index + 1}. ${entry.website} (${entry.username})`);
    });

    // Retrieve a specific password
    console.log('\n🔍 Retrieving GitHub password...');
    const githubPassword = await pm.getPassword('github.com', 'my-username');
    console.log('✅ Retrieved GitHub password successfully');
    console.log(`   Website: ${githubPassword.website}`);
    console.log(`   Username: ${githubPassword.username}`);
    console.log(`   Password: ${githubPassword.password}`);
    console.log(`   Created: ${githubPassword.createdAt.toISOString()}`);

    // Search for passwords
    console.log('\n🔎 Searching for passwords containing "example"...');
    const searchResults = await pm.searchPasswords('example');
    console.log(`Found ${searchResults.length} matching passwords:`);
    searchResults.forEach((entry, index) => {
      console.log(`   ${index + 1}. ${entry.website} (${entry.username})`);
    });

    // Update a password
    console.log('\n✏️  Updating GitHub password...');
    await pm.updatePassword('github.com', 'my-username', 'new-super-secret-password-456');
    console.log('✅ GitHub password updated');

    // Verify the update
    const updatedPassword = await pm.getPassword('github.com', 'my-username');
    console.log(`   New password: ${updatedPassword.password}`);

    // Export data (encrypted)
    console.log('\n📦 Exporting encrypted data...');
    const exportData = await pm.exportData();
    console.log('✅ Data exported successfully');
    console.log(`   Export size: ${exportData.length} bytes`);

    // Test the backend switching capability
    console.log('\n🔄 Testing backend information...');
    const currentBackend = manager.getCurrentBackend();
    console.log(`   Current backend: ${currentBackend}`);
    
    // Clean up - remove a password
    console.log('\n🗑️  Removing work VPN password...');
    await pm.removePassword('work-vpn', 'employee-id');
    console.log('✅ Work VPN password removed');

    // Final password count
    const finalPasswords = await pm.listPasswords();
    console.log(`\n📈 Final password count: ${finalPasswords.length}`);

    console.log('\n✅ Native Secure Enclave example completed successfully!');
    console.log('\n🔐 Security Features Demonstrated:');
    console.log('   • Hardware-backed key generation');
    console.log('   • Biometric/passcode access control');
    console.log('   • Secure encryption/decryption');
    console.log('   • Private keys never leave Secure Enclave');
    console.log('   • Age-encrypted password storage');

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    
    if (error.message.includes('Native Secure Enclave addon not available')) {
      console.log('\n💡 To fix this issue:');
      console.log('   1. Make sure you\'re on macOS');
      console.log('   2. Build the native addon: npm run build:native');
      console.log('   3. Ensure your Mac has Secure Enclave support');
    }
    
    if (error.message.includes('User authentication required')) {
      console.log('\n💡 This error occurs when:');
      console.log('   • Touch ID/Face ID authentication is required');
      console.log('   • Device passcode is required');
      console.log('   • The device is locked');
    }
  }
}

// Run the example
if (require.main === module) {
  runExample().catch(console.error);
}

module.exports = { runExample }; 