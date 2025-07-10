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
    // For now, just return an error since there seems to be a fundamental issue
    // with the parameter handling that needs to be investigated further
    let errorString = strdup("Encryption not supported yet - parameter handling issue")
    errorOut.pointee = errorString
    return false
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
    // For now, just return an error to test if the issue is in the C interface
    let errorString = strdup("Decryption not implemented")
    errorOut.pointee = errorString
    return false
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
}

public class SecureEnclaveManager {
    public static func generateKeyPair(accessControl: String) throws -> SecureEnclaveKeyPair {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        // For initial testing, use minimal access control
        let context = LAContext()
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
            
            let publicKeyData = privateKey.publicKey.rawRepresentation
            let privateKeyData = privateKey.dataRepresentation
            
            return SecureEnclaveKeyPair(
                publicKey: publicKeyData,
                privateKeyData: privateKeyData
            )
        } catch {
            throw SecureEnclaveError.keyGenerationFailed
        }
    }
    
    public static func encrypt(data: Data, publicKey: Data) throws -> Data {
        do {
            let publicKeyObj = try P256.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            let ephemeralKey = P256.KeyAgreement.PrivateKey()
            
            let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: publicKeyObj)
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: Data(),
                outputByteCount: 32
            )
            
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            
            var result = Data()
            result.append(ephemeralKey.publicKey.rawRepresentation)
            if let combined = sealedBox.combined {
                result.append(combined)
            } else {
                throw SecureEnclaveError.encryptionFailed
            }
            
            return result
        } catch {
            throw SecureEnclaveError.encryptionFailed
        }
    }
    
    public static func decrypt(ciphertext: Data, privateKeyData: Data) throws -> Data {
        // For now, just return an error since we can't reliably reconstruct Secure Enclave private keys
        // from their data representation for decryption operations
        throw SecureEnclaveError.decryptionFailed
    }
    
    public static func deleteKey(privateKeyData: Data) throws {
        // For Secure Enclave keys, deletion is managed by the system
        // This is a no-op placeholder
    }
} 