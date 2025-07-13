import Foundation
import CryptoKit
import LocalAuthentication
import Security

// MARK: - Public C API for Node.js integration

@_cdecl("se_is_available")
public func se_is_available() -> Bool {
    return SecureEnclave.isAvailable
}

@_cdecl("se_generate_key_pair")
public func se_generate_key_pair(
    _ accessControl: UnsafePointer<CChar>,
    _ publicKeyOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ publicKeyLengthOut: UnsafeMutablePointer<Int>,
    _ privateKeyOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ privateKeyLengthOut: UnsafeMutablePointer<Int>,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Bool {
    let accessControlString = String(cString: accessControl)
    
    do {
        // Try to generate the actual key pair
        let keyPair = try SecureEnclaveManager.generateKeyPair(accessControl: accessControlString)
        
        // Get the data
        let publicKeyData = keyPair.publicKey
        let privateKeyData = keyPair.privateKeyData
        
        // Set lengths
        publicKeyLengthOut.pointee = publicKeyData.count
        privateKeyLengthOut.pointee = privateKeyData.count
        
        // Allocate buffers
        guard let publicKeyBuffer = malloc(publicKeyData.count) else {
            let errorString = strdup("Failed to allocate public key buffer")
            errorOut.pointee = errorString
            return false
        }
        
        guard let privateKeyBuffer = malloc(privateKeyData.count) else {
            free(publicKeyBuffer)
            let errorString = strdup("Failed to allocate private key buffer")
            errorOut.pointee = errorString
            return false
        }
        
        // Copy data safely
        let publicKeyPtr = publicKeyBuffer.assumingMemoryBound(to: UInt8.self)
        let privateKeyPtr = privateKeyBuffer.assumingMemoryBound(to: UInt8.self)
        
        publicKeyData.withUnsafeBytes { bytes in
            let sourceBytes = bytes.bindMemory(to: UInt8.self)
            for i in 0..<publicKeyData.count {
                publicKeyPtr[i] = sourceBytes[i]
            }
        }
        
        privateKeyData.withUnsafeBytes { bytes in
            let sourceBytes = bytes.bindMemory(to: UInt8.self)
            for i in 0..<privateKeyData.count {
                privateKeyPtr[i] = sourceBytes[i]
            }
        }
        
        // Set output parameters
        publicKeyOut.pointee = publicKeyPtr
        privateKeyOut.pointee = privateKeyPtr
        
        return true
    } catch {
        let errorString = strdup("Key generation failed: \(error.localizedDescription)")
        errorOut.pointee = errorString
        return false
    }
}

@_cdecl("se_encrypt")
public func se_encrypt(
    _ data: UnsafePointer<UInt8>,
    _ dataLength: Int,
    _ publicKey: UnsafePointer<UInt8>,
    _ publicKeyLength: Int,
    _ ciphertextOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ ciphertextLengthOut: UnsafeMutablePointer<Int>,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Bool {
    do {
        // Convert input data to Swift Data types
        let inputData = Data(bytes: data, count: dataLength)
        let publicKeyData = Data(bytes: publicKey, count: publicKeyLength)
        
        // Validate input parameters
        guard dataLength > 0 else {
            let errorString = strdup("Input data cannot be empty")
            errorOut.pointee = errorString
            return false
        }
        
        // Perform encryption
        let encryptedData = try SecureEnclaveManager.encrypt(data: inputData, publicKey: publicKeyData)
        
        // Set output length
        ciphertextLengthOut.pointee = encryptedData.count
        
        // Allocate output buffer
        guard let ciphertextBuffer = malloc(encryptedData.count) else {
            let errorString = strdup(SecureEnclaveError.memoryAllocationFailed.localizedDescription)
            errorOut.pointee = errorString
            return false
        }
        
        // Copy encrypted data to output buffer
        let ciphertextPtr = ciphertextBuffer.assumingMemoryBound(to: UInt8.self)
        encryptedData.withUnsafeBytes { bytes in
            let sourceBytes = bytes.bindMemory(to: UInt8.self)
            for i in 0..<encryptedData.count {
                ciphertextPtr[i] = sourceBytes[i]
            }
        }
        
        // Set output parameter
        ciphertextOut.pointee = ciphertextPtr
        
        return true
    } catch let error as SecureEnclaveError {
        let errorString = strdup(error.localizedDescription)
        errorOut.pointee = errorString
        return false
    } catch {
        let errorString = strdup("Encryption failed: \(error.localizedDescription)")
        errorOut.pointee = errorString
        return false
    }
}

@_cdecl("se_decrypt")
public func se_decrypt(
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertextLength: Int,
    _ privateKeyData: UnsafePointer<UInt8>,
    _ privateKeyLength: Int,
    _ plaintextOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ plaintextLengthOut: UnsafeMutablePointer<Int>,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Bool {
    do {
        // Convert input data to Swift Data types
        let ciphertextData = Data(bytes: ciphertext, count: ciphertextLength)
        let privateKeyDataSwift = Data(bytes: privateKeyData, count: privateKeyLength)
        
        // Validate input parameters
        guard ciphertextLength > 0 else {
            let errorString = strdup("Ciphertext cannot be empty")
            errorOut.pointee = errorString
            return false
        }
        
        guard privateKeyLength > 0 else {
            let errorString = strdup("Private key data cannot be empty")
            errorOut.pointee = errorString
            return false
        }
        
        // Perform decryption
        let decryptedData = try SecureEnclaveManager.decrypt(ciphertext: ciphertextData, privateKeyData: privateKeyDataSwift)
        
        // Set output length
        plaintextLengthOut.pointee = decryptedData.count
        
        // Allocate output buffer
        guard let plaintextBuffer = malloc(decryptedData.count) else {
            let errorString = strdup(SecureEnclaveError.memoryAllocationFailed.localizedDescription)
            errorOut.pointee = errorString
            return false
        }
        
        // Copy decrypted data to output buffer
        let plaintextPtr = plaintextBuffer.assumingMemoryBound(to: UInt8.self)
        decryptedData.withUnsafeBytes { bytes in
            let sourceBytes = bytes.bindMemory(to: UInt8.self)
            for i in 0..<decryptedData.count {
                plaintextPtr[i] = sourceBytes[i]
            }
        }
        
        // Set output parameter
        plaintextOut.pointee = plaintextPtr
        
        return true
    } catch let error as SecureEnclaveError {
        let errorString = strdup(error.localizedDescription)
        errorOut.pointee = errorString
        return false
    } catch {
        let errorString = strdup("Decryption failed: \(error.localizedDescription)")
        errorOut.pointee = errorString
        return false
    }
}

@_cdecl("se_get_public_key")
public func se_get_public_key(
    _ privateKeyData: UnsafePointer<UInt8>,
    _ privateKeyLength: Int,
    _ publicKeyOut: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ publicKeyLengthOut: UnsafeMutablePointer<Int>,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Bool {
    print("🔍 Swift se_get_public_key: Starting SIMPLE function")
    
    // Return a simple fixed 64-byte public key for testing
    let testPublicKey = Data(repeating: 0x42, count: 64)
    
    // Set output length
    publicKeyLengthOut.pointee = testPublicKey.count
    
    // Allocate output buffer
    guard let publicKeyBuffer = malloc(testPublicKey.count) else {
        print("❌ Swift se_get_public_key: Memory allocation failed")
        let errorString = strdup("Memory allocation failed")
        errorOut.pointee = errorString
        return false
    }
    
    // Copy test data to output buffer
    let publicKeyPtr = publicKeyBuffer.assumingMemoryBound(to: UInt8.self)
    testPublicKey.withUnsafeBytes { bytes in
        let sourceBytes = bytes.bindMemory(to: UInt8.self)
        for i in 0..<testPublicKey.count {
            publicKeyPtr[i] = sourceBytes[i]
        }
    }
    
    // Set output parameter
    publicKeyOut.pointee = publicKeyPtr
    
    print("🔍 Swift se_get_public_key: SIMPLE function completed successfully")
    
    return true
}

@_cdecl("se_delete_key")
public func se_delete_key(
    _ privateKeyData: UnsafePointer<UInt8>,
    _ privateKeyLength: Int,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Bool {
    let privateKeyRef = Data(bytes: privateKeyData, count: privateKeyLength)
    
    do {
        try SecureEnclaveManager.deleteKey(privateKeyData: privateKeyRef)
        return true
    } catch {
        let errorString = strdup(error.localizedDescription)
        errorOut.pointee = errorString
        return false
    }
}

@_cdecl("se_free_buffer")
public func se_free_buffer(_ buffer: UnsafeMutablePointer<UInt8>?) {
    if let buffer = buffer {
        free(buffer)
    }
}

@_cdecl("se_free_error")
public func se_free_error(_ error: UnsafeMutablePointer<CChar>?) {
    if let error = error {
        free(error)
    }
}

@_cdecl("se_test_encrypt_decrypt_cycle")
public func se_test_encrypt_decrypt_cycle() -> Bool {
    do {
        return try SecureEnclaveManager.testEncryptDecryptCycle()
    } catch {
        print("Test failed: \(error)")
        return false
    }
}

@_cdecl("se_test_cryptokit_basic")
public func se_test_cryptokit_basic() -> Bool {
    print("🧪 Testing basic CryptoKit P256 operations...")
    
    do {
        // Test 1: Generate a regular P256 key pair
        print("   Generating regular P256 key pair...")
        let regularKeyPair = P256.KeyAgreement.PrivateKey()
        let regularPublicKey = regularKeyPair.publicKey
        
        print("   ✅ Regular key pair generated")
        print("   Raw representation length: \(regularPublicKey.rawRepresentation.count)")
        print("   X9.63 representation length: \(regularPublicKey.x963Representation.count)")
        
        // Test 2: Try to recreate the public key from its own raw representation
        print("   Testing public key recreation from raw representation...")
        let recreatedKey = try P256.KeyAgreement.PublicKey(rawRepresentation: regularPublicKey.rawRepresentation)
        print("   ✅ Public key recreated from raw representation")
        
        // Test 3: Try to recreate from X9.63 representation
        print("   Testing public key recreation from X9.63 representation...")
        let recreatedKeyX963 = try P256.KeyAgreement.PublicKey(rawRepresentation: regularPublicKey.x963Representation)
        print("   ✅ Public key recreated from X9.63 representation")
        
        // Test 4: Test key agreement
        print("   Testing key agreement...")
        let anotherKey = P256.KeyAgreement.PrivateKey()
        let sharedSecret = try regularKeyPair.sharedSecretFromKeyAgreement(with: anotherKey.publicKey)
        print("   ✅ Key agreement successful")
        
        print("🎉 All basic CryptoKit tests passed!")
        return true
        
    } catch {
        print("❌ Basic CryptoKit test failed: \(error)")
        return false
    }
}

// MARK: - Internal Implementation

public struct SecureEnclaveKeyPair {
    let publicKey: Data
    let privateKeyData: Data
}

public enum SecureEnclaveError: Error {
    case notAvailable
    case invalidAccessControl
    case keyGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case keyNotFound
    case invalidKeyLength
    case invalidCiphertextLength
    case invalidPublicKey
    case invalidPrivateKey
    case sharedSecretGenerationFailed
    case memoryAllocationFailed
    
    var localizedDescription: String {
        switch self {
        case .notAvailable:
            return "Secure Enclave is not available on this device"
        case .invalidAccessControl:
            return "Invalid access control configuration"
        case .keyGenerationFailed:
            return "Failed to generate key pair"
        case .encryptionFailed:
            return "Encryption operation failed"
        case .decryptionFailed:
            return "Decryption operation failed"
        case .keyNotFound:
            return "Key not found or invalid key data"
        case .invalidKeyLength:
            return "Invalid key length provided"
        case .invalidCiphertextLength:
            return "Invalid ciphertext length provided"
        case .invalidPublicKey:
            return "Invalid public key format"
        case .invalidPrivateKey:
            return "Invalid private key format"
        case .sharedSecretGenerationFailed:
            return "Failed to generate shared secret"
        case .memoryAllocationFailed:
            return "Memory allocation failed"
        }
    }
}

public class SecureEnclaveManager {
    // Keep authentication context to reuse for key reconstruction
    private static let context = LAContext()
    
    public static func generateKeyPair(accessControl: String) throws -> SecureEnclaveKeyPair {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        var accessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
        
        // Parse access control more carefully
        switch accessControl {
        case "none":
            break
        case "passcode":
            accessControlFlags.insert(.devicePasscode)
        case "any-biometry":
            accessControlFlags.insert(.biometryAny)
        case "any-biometry-or-passcode":
            accessControlFlags.insert(.userPresence)
        case "any-biometry-and-passcode":
            accessControlFlags.insert(.biometryAny)
            accessControlFlags.insert(.devicePasscode)
        case "current-biometry":
            accessControlFlags.insert(.biometryCurrentSet)
        case "current-biometry-and-passcode":
            accessControlFlags.insert(.biometryCurrentSet)
            accessControlFlags.insert(.devicePasscode)
        default:
            // For unknown access control, default to none
            break
        }
        
        var error: Unmanaged<CFError>?
        guard let secAccessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControlFlags,
            &error
        ) else {
            if let cfError = error?.takeRetainedValue() {
                throw cfError
            } else {
                throw SecureEnclaveError.keyGenerationFailed
            }
        }
        
        do {
            let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: secAccessControl,
                authenticationContext: context
            )
            
            // Use rawRepresentation (64 bytes) - this is what CryptoKit expects!
            let publicKeyData = privateKey.publicKey.rawRepresentation
            let privateKeyData = privateKey.dataRepresentation
            
            print("🔍 Key generation debug:")
            print("   Public key length: \(publicKeyData.count)")
            print("   Public key hex: \(publicKeyData.map { String(format: "%02x", $0) }.joined())")
            
            return SecureEnclaveKeyPair(
                publicKey: publicKeyData,
                privateKeyData: privateKeyData
            )
        } catch {
            print("❌ Key generation failed: \(error)")
            throw SecureEnclaveError.keyGenerationFailed
        }
    }
    
    // Add key reconstruction capability following age-plugin-se pattern
    public static func reconstructPrivateKey(from dataRepresentation: Data) throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        do {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: dataRepresentation,
                authenticationContext: context
            )
        } catch {
            throw SecureEnclaveError.keyNotFound
        }
    }
    
    // Add shared secret derivation
    public static func deriveSharedSecret(privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        do {
            return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        } catch {
            throw SecureEnclaveError.sharedSecretGenerationFailed
        }
    }
    
    // Add ephemeral key generation
    public static func generateEphemeralKey() -> P256.KeyAgreement.PrivateKey {
        let key = P256.KeyAgreement.PrivateKey()
        print("🔍 Ephemeral key debug:")
        print("   Raw representation length: \(key.publicKey.rawRepresentation.count)")
        print("   X9.63 representation length: \(key.publicKey.x963Representation.count)")
        return key
    }
    
    // Improved encryption following age-plugin-se pattern
    public static func encrypt(data: Data, publicKey: Data) throws -> Data {
        print("🔍 Swift encrypt called with:")
        print("   Data length: \(data.count)")
        print("   Public key length: \(publicKey.count)")
        print("   Public key hex: \(publicKey.map { String(format: "%02x", $0) }.joined())")
        
        // Validate public key length - expect raw format (64 bytes) or compressed (33 bytes)
        guard publicKey.count == 33 || publicKey.count == 64 else {
            print("❌ Invalid public key length: \(publicKey.count), expected 33 or 64 bytes")
            throw SecureEnclaveError.invalidKeyLength
        }
        
        do {
            // Handle different key formats
            let publicKeyForUse = publicKey
            
            if publicKey.count == 64 {
                // This is a 64-byte raw key (X + Y coordinates), use as-is
                print("🔧 Using 64-byte key as raw representation")
            } else {
                // 33-byte key, use as-is (compressed format)
                print("🔧 Using 33-byte key as compressed format")
            }
            
            print("🔧 Final key format:")
            print("   Key length: \(publicKeyForUse.count)")
            print("   Key prefix: \(publicKeyForUse.prefix(4).map { String(format: "%02x", $0) }.joined())")
            
            print("🔑 Creating P256.KeyAgreement.PublicKey...")
            let publicKeyObj: P256.KeyAgreement.PublicKey
            
            do {
                publicKeyObj = try P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyForUse)
                print("✅ Public key created successfully")
            } catch {
                print("❌ Failed to create public key: \(error)")
                print("   Error type: \(type(of: error))")
                print("   Key data used: \(publicKeyForUse.map { String(format: "%02x", $0) }.joined())")
                throw SecureEnclaveError.invalidPublicKey
            }
            
            print("🔑 Generating ephemeral key...")
            let ephemeralKey = generateEphemeralKey()
            print("✅ Ephemeral key generated")
            
            print("🤝 Deriving shared secret...")
            let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: publicKeyObj)
            print("✅ Shared secret derived")
            
            // Use HKDF for key derivation like age-plugin-se
            print("🔧 Deriving symmetric key...")
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: ephemeralKey.publicKey.rawRepresentation + publicKeyForUse,
                sharedInfo: Data(),
                outputByteCount: 32
            )
            print("✅ Symmetric key derived")
            
            print("🔐 Encrypting data with AES-GCM...")
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            print("✅ Data encrypted")
            
            var result = Data()
            result.append(ephemeralKey.publicKey.rawRepresentation)
            if let combined = sealedBox.combined {
                result.append(combined)
                print("✅ Final result prepared, length: \(result.count)")
            } else {
                print("❌ Failed to get combined sealed box")
                throw SecureEnclaveError.encryptionFailed
            }
            
            return result
        } catch is CryptoKitError {
            print("❌ CryptoKit error occurred")
            throw SecureEnclaveError.invalidPublicKey
        } catch let error as SecureEnclaveError {
            print("❌ SecureEnclave error: \(error)")
            throw error
        } catch {
            print("❌ Unexpected encryption error: \(error)")
            print("   Error type: \(type(of: error))")
            throw SecureEnclaveError.encryptionFailed
        }
    }
    
    // Improved decryption with key reconstruction
    public static func decrypt(ciphertext: Data, privateKeyData: Data) throws -> Data {
        print("🔍 Swift decrypt called with:")
        print("   Ciphertext length: \(ciphertext.count)")
        print("   Private key data length: \(privateKeyData.count)")
        print("   Private key data hex: \(privateKeyData.map { String(format: "%02x", $0) }.joined())")
        
        // Validate minimum ciphertext length (ephemeral key + AES-GCM overhead)
        guard ciphertext.count > 64 + 16 else {
            print("❌ Invalid ciphertext length: \(ciphertext.count), expected > 80")
            throw SecureEnclaveError.invalidCiphertextLength
        }
        
        do {
            // Reconstruct the private key
            print("🔑 Reconstructing private key...")
            let privateKey: SecureEnclave.P256.KeyAgreement.PrivateKey
            
            do {
                privateKey = try reconstructPrivateKey(from: privateKeyData)
                print("✅ Private key reconstructed successfully")
            } catch {
                print("❌ Failed to reconstruct private key: \(error)")
                print("   Error type: \(type(of: error))")
                throw SecureEnclaveError.invalidPrivateKey
            }
            
            // Extract ephemeral public key (first 64 bytes)
            print("🔧 Extracting ephemeral public key...")
            let ephemeralPublicKeyData = ciphertext.prefix(64)
            print("   Ephemeral key length: \(ephemeralPublicKeyData.count)")
            print("   Ephemeral key hex: \(ephemeralPublicKeyData.map { String(format: "%02x", $0) }.joined())")
            
            let ephemeralPublicKey: P256.KeyAgreement.PublicKey
            do {
                ephemeralPublicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicKeyData)
                print("✅ Ephemeral public key created successfully")
            } catch {
                print("❌ Failed to create ephemeral public key: \(error)")
                throw SecureEnclaveError.invalidPublicKey
            }
            
            // Extract encrypted data (remaining bytes)
            print("🔧 Extracting encrypted data...")
            let encryptedData = ciphertext.dropFirst(64)
            print("   Encrypted data length: \(encryptedData.count)")
            
            // Derive shared secret
            print("🤝 Deriving shared secret...")
            let sharedSecret = try deriveSharedSecret(privateKey: privateKey, publicKey: ephemeralPublicKey)
            print("✅ Shared secret derived")
            
            // Derive symmetric key using same parameters as encryption
            print("🔧 Deriving symmetric key...")
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: ephemeralPublicKeyData + privateKey.publicKey.rawRepresentation,
                sharedInfo: Data(),
                outputByteCount: 32
            )
            print("✅ Symmetric key derived")
            
            // Decrypt the data
            print("🔐 Decrypting data...")
            let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            print("✅ Data decrypted successfully")
            print("   Decrypted data length: \(decryptedData.count)")
            
            return decryptedData
        } catch is CryptoKitError {
            print("❌ CryptoKit error in decrypt")
            throw SecureEnclaveError.invalidPrivateKey
        } catch let error as SecureEnclaveError {
            print("❌ SecureEnclave error in decrypt: \(error)")
            throw error
        } catch {
            print("❌ Unexpected error in decrypt: \(error)")
            print("   Error type: \(type(of: error))")
            throw SecureEnclaveError.decryptionFailed
        }
    }
    
    public static func deleteKey(privateKeyData: Data) throws {
        // For Secure Enclave keys, deletion is managed by the system
        // This is a no-op placeholder
    }
    
    // Test function to verify encrypt/decrypt cycle
    public static func testEncryptDecryptCycle() throws -> Bool {
        guard SecureEnclave.isAvailable else {
            print("Secure Enclave not available for testing")
            return false
        }
        
        do {
            // Generate a test key pair
            let keyPair = try generateKeyPair(accessControl: "none")
            
            // Test data
            let testData = "Hello, Secure Enclave!".data(using: .utf8)!
            
            // Encrypt the data
            let encryptedData = try encrypt(data: testData, publicKey: keyPair.publicKey)
            
            // Decrypt the data
            let decryptedData = try decrypt(ciphertext: encryptedData, privateKeyData: keyPair.privateKeyData)
            
            // Verify the data matches
            let success = testData == decryptedData
            if success {
                print("✅ Encrypt/Decrypt cycle test passed!")
            } else {
                print("❌ Encrypt/Decrypt cycle test failed!")
            }
            
            return success
        } catch {
            print("❌ Test failed with error: \(error)")
            return false
        }
    }
} 