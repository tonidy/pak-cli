#!/usr/bin/env node

/**
 * Direct test of the native Secure Enclave implementation
 * This bypasses the age recipient format and tests the raw key operations
 */

const native = require('./index.js');

async function testNativeSE() {
    console.log('🧪 Testing Native Secure Enclave Implementation');
    console.log('================================================');
    
    // Check availability
    console.log('✓ Checking SE availability...');
    if (!native.isAvailable()) {
        console.error('❌ Secure Enclave not available');
        process.exit(1);
    }
    console.log('✅ Secure Enclave is available');
    
    try {
        // Test 1: Key Generation
        console.log('\n🔑 Testing key generation...');
        const keyPair = await native.generateKeyPair('none');
        console.log(`✅ Key pair generated successfully`);
        console.log(`   Public key: ${keyPair.publicKey.length} bytes`);
        console.log(`   Private key: ${keyPair.privateKey.length} bytes`);
        console.log(`   Public key (hex): ${keyPair.publicKey.toString('hex')}`);
        
        // Test 2: Encrypt/Decrypt Cycle
        console.log('\n🔐 Testing encrypt/decrypt cycle...');
        const testData = Buffer.from('Hello, Native Secure Enclave! 🚀');
        console.log(`   Test data: "${testData.toString()}"`);
        console.log(`   Test data length: ${testData.length} bytes`);
        
        console.log('   Encrypting...');
        const encrypted = await native.encrypt(testData, keyPair.publicKey);
        console.log(`✅ Encryption successful`);
        console.log(`   Encrypted data length: ${encrypted.length} bytes`);
        console.log(`   Encrypted data (first 32 bytes): ${encrypted.slice(0, 32).toString('hex')}`);
        
        console.log('   Decrypting...');
        const decrypted = await native.decrypt(encrypted, keyPair.privateKey);
        console.log(`✅ Decryption successful`);
        console.log(`   Decrypted data: "${decrypted.toString()}"`);
        
        // Test 3: Verify data integrity
        console.log('\n🔍 Verifying data integrity...');
        if (testData.equals(decrypted)) {
            console.log('✅ Data integrity verified - decrypted data matches original!');
        } else {
            console.error('❌ Data integrity check failed');
            console.log(`   Original:  ${testData.toString('hex')}`);
            console.log(`   Decrypted: ${decrypted.toString('hex')}`);
            process.exit(1);
        }
        
        // Test 4: Multiple encrypt/decrypt cycles
        console.log('\n🔄 Testing multiple encrypt/decrypt cycles...');
        for (let i = 1; i <= 3; i++) {
            const testMessage = `Test message ${i} - ${new Date().toISOString()}`;
            const testBuffer = Buffer.from(testMessage);
            
            const enc = await native.encrypt(testBuffer, keyPair.publicKey);
            const dec = await native.decrypt(enc, keyPair.privateKey);
            
            if (testBuffer.equals(dec)) {
                console.log(`   ✅ Cycle ${i}: "${testMessage}"`);
            } else {
                console.error(`   ❌ Cycle ${i} failed`);
                process.exit(1);
            }
        }
        
        console.log('\n🎉 All tests passed! Native Secure Enclave is working correctly!');
        console.log('================================================');
        
    } catch (error) {
        console.error('\n❌ Test failed:', error.message);
        console.error('Error details:', error);
        process.exit(1);
    }
}

// Run the test
testNativeSE().catch(error => {
    console.error('Unexpected error:', error);
    process.exit(1);
}); 