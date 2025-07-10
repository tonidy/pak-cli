import XCTest
@testable import SecureEnclaveSwift

final class SecureEnclaveSwiftTests: XCTestCase {
    
    func testSecureEnclaveAvailability() {
        // Test that we can check SE availability
        let available = se_is_available()
        print("Secure Enclave available: \(available)")
        // Don't assert on availability since it depends on hardware
    }
    
    func testKeyGeneration() throws {
        guard se_is_available() else {
            throw XCTSkip("Secure Enclave not available")
        }
        
        var publicKey: UnsafeMutablePointer<UInt8>?
        var publicKeyLength: Int = 0
        var privateKey: UnsafeMutablePointer<UInt8>?
        var privateKeyLength: Int = 0
        var error: UnsafeMutablePointer<CChar>?
        
        let success = se_generate_key_pair(
            "any-biometry-or-passcode",
            &publicKey,
            &publicKeyLength,
            &privateKey,
            &privateKeyLength,
            &error
        )
        
        if !success {
            if let errorPtr = error {
                let errorString = String(cString: errorPtr)
                se_free_error(errorPtr)
                XCTFail("Key generation failed: \(errorString)")
            } else {
                XCTFail("Key generation failed with unknown error")
            }
        } else {
            XCTAssertNotNil(publicKey)
            XCTAssertGreaterThan(publicKeyLength, 0)
            XCTAssertNotNil(privateKey)
            XCTAssertGreaterThan(privateKeyLength, 0)
            
            // Clean up
            se_free_buffer(publicKey)
            se_free_buffer(privateKey)
        }
    }
    
    func testEncryptionDecryption() throws {
        guard se_is_available() else {
            throw XCTSkip("Secure Enclave not available")
        }
        
        // First generate a key pair
        var publicKey: UnsafeMutablePointer<UInt8>?
        var publicKeyLength: Int = 0
        var privateKey: UnsafeMutablePointer<UInt8>?
        var privateKeyLength: Int = 0
        var error: UnsafeMutablePointer<CChar>?
        
        let keyGenSuccess = se_generate_key_pair(
            "any-biometry-or-passcode",
            &publicKey,
            &publicKeyLength,
            &privateKey,
            &privateKeyLength,
            &error
        )
        
        guard keyGenSuccess else {
            if let errorPtr = error {
                let errorString = String(cString: errorPtr)
                se_free_error(errorPtr)
                XCTFail("Key generation failed: \(errorString)")
            }
            return
        }
        
        // Test data
        let testData = "Hello, Secure Enclave!".data(using: .utf8)!
        
        // Encrypt
        var ciphertext: UnsafeMutablePointer<UInt8>?
        var ciphertextLength: Int = 0
        
        let encryptSuccess = se_encrypt(
            testData.withUnsafeBytes { $0.bindMemory(to: UInt8.self).baseAddress! },
            testData.count,
            publicKey!,
            publicKeyLength,
            &ciphertext,
            &ciphertextLength,
            &error
        )
        
        guard encryptSuccess else {
            if let errorPtr = error {
                let errorString = String(cString: errorPtr)
                se_free_error(errorPtr)
                XCTFail("Encryption failed: \(errorString)")
            }
            return
        }
        
        // Decrypt
        var plaintext: UnsafeMutablePointer<UInt8>?
        var plaintextLength: Int = 0
        
        let decryptSuccess = se_decrypt(
            ciphertext!,
            ciphertextLength,
            privateKey!,
            privateKeyLength,
            &plaintext,
            &plaintextLength,
            &error
        )
        
        guard decryptSuccess else {
            if let errorPtr = error {
                let errorString = String(cString: errorPtr)
                se_free_error(errorPtr)
                XCTFail("Decryption failed: \(errorString)")
            }
            return
        }
        
        // Verify decrypted data matches original
        let decryptedData = Data(bytes: plaintext!, count: plaintextLength)
        XCTAssertEqual(testData, decryptedData)
        
        // Clean up
        se_free_buffer(publicKey)
        se_free_buffer(privateKey)
        se_free_buffer(ciphertext)
        se_free_buffer(plaintext)
    }
} 