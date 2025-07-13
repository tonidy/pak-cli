#!/usr/bin/env node

/**
 * Test CryptoKit compatibility - test if our encryption function works with regular keys
 */

const native = require('./index.js');

async function testCryptoKitCompatibility() {
    console.log('🧪 Testing CryptoKit Compatibility');
    console.log('==================================');
    
    // Check availability
    console.log('✓ Checking SE availability...');
    if (!native.isAvailable()) {
        console.error('❌ Secure Enclave not available');
        process.exit(1);
    }
    console.log('✅ Secure Enclave is available');
    
    try {
        // Generate a regular P256 key pair using Node.js crypto (should be compatible with CryptoKit)
        console.log('\n🔑 Generating regular P256 key pair for comparison...');
        
        const crypto = require('crypto');
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1', // P-256
            publicKeyEncoding: {
                type: 'spki',
                format: 'der'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der'
            }
        });
        
        // Extract the public key in uncompressed format (should be 65 bytes)
        // For SPKI format, the actual public key starts after the header
        // Let's extract it manually
        console.log('   Full SPKI public key length:', publicKey.length);
        console.log('   Full SPKI public key hex:', publicKey.toString('hex'));
        
        // For P256 SPKI, the public key is typically at the end (65 bytes)
        const publicKeyRaw = publicKey.slice(-65);
        console.log('   Extracted public key length:', publicKeyRaw.length);
        console.log('   Extracted public key hex:', publicKeyRaw.toString('hex'));
        console.log('   Starts with 0x04?', publicKeyRaw[0] === 0x04);
        
        // Test our encryption with this regular key
        console.log('\n🔐 Testing encryption with regular CryptoKit-compatible key...');
        const testData = Buffer.from('Hello, Regular CryptoKit Key! 🔑');
        console.log(`   Test data: "${testData.toString()}"`);
        
        try {
            const encrypted = await native.encrypt(testData, publicKeyRaw);
            console.log('✅ Encryption with regular key succeeded!');
            console.log(`   Encrypted data length: ${encrypted.length}`);
            
            // Note: We can't test decryption because we'd need to import the private key into SE
            // But successful encryption proves our function works with proper key formats
            
        } catch (error) {
            console.error('❌ Encryption with regular key failed:', error.message);
            
            // Try with a manually created test key
            console.log('\n🔧 Trying with a manually created test key...');
            
            // Create a simple test key (this might not be a valid curve point, but tests the format)
            const testKey = Buffer.alloc(65);
            testKey[0] = 0x04; // Uncompressed format prefix
            // Fill with some test data (this won't be a valid curve point, but tests format)
            for (let i = 1; i < 65; i++) {
                testKey[i] = i % 256;
            }
            
            console.log('   Test key length:', testKey.length);
            console.log('   Test key prefix:', testKey.slice(0, 4).toString('hex'));
            
            try {
                const encrypted2 = await native.encrypt(testData, testKey);
                console.log('✅ Encryption with test key succeeded!');
            } catch (error2) {
                console.error('❌ Encryption with test key also failed:', error2.message);
            }
        }
        
    } catch (error) {
        console.error('\n❌ Test failed:', error.message);
        console.error('Error details:', error);
        process.exit(1);
    }
}

// Run the test
testCryptoKitCompatibility().catch(error => {
    console.error('Unexpected error:', error);
    process.exit(1);
}); 