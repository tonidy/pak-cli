#include <napi.h>
#include <string>
#include <vector>
#include <memory>
#include <iostream> // Added for debug output

// C function declarations from Swift
extern "C" {
    bool se_is_available();
    
    bool se_generate_key_pair(
        const char* accessControl,
        unsigned char** publicKeyOut,
        int* publicKeyLengthOut,
        unsigned char** privateKeyOut,
        int* privateKeyLengthOut,
        char** errorOut
    );
    
    bool se_encrypt(
        const unsigned char* data,
        int dataLength,
        const unsigned char* publicKey,
        int publicKeyLength,
        unsigned char** ciphertextOut,
        int* ciphertextLengthOut,
        char** errorOut
    );
    
    bool se_decrypt(
        const unsigned char* ciphertext,
        int ciphertextLength,
        const unsigned char* privateKeyData,
        int privateKeyLength,
        unsigned char** plaintextOut,
        int* plaintextLengthOut,
        char** errorOut
    );
    
    bool se_get_public_key(
        const unsigned char* privateKeyData,
        int privateKeyLength,
        unsigned char** publicKeyOut,
        int* publicKeyLengthOut,
        char** errorOut
    );
    
    bool se_delete_key(
        const unsigned char* privateKeyData,
        int privateKeyLength,
        char** errorOut
    );
    
    bool se_test_encrypt_decrypt_cycle();
    
    bool se_test_cryptokit_basic();
    
    void se_free_buffer(unsigned char* buffer);
    void se_free_error(char* error);
}

// Helper class for RAII memory management
class SwiftBuffer {
public:
    SwiftBuffer(unsigned char* ptr) : ptr_(ptr) {}
    ~SwiftBuffer() {
        if (ptr_) {
            se_free_buffer(ptr_);
        }
    }
    
    unsigned char* get() const { return ptr_; }
    unsigned char* release() {
        unsigned char* temp = ptr_;
        ptr_ = nullptr;
        return temp;
    }
    
private:
    unsigned char* ptr_;
};

class SwiftError {
public:
    SwiftError(char* ptr) : ptr_(ptr) {}
    ~SwiftError() {
        if (ptr_) {
            se_free_error(ptr_);
        }
    }
    
    char* get() const { return ptr_; }
    
private:
    char* ptr_;
};

// JavaScript wrapper functions
Napi::Boolean IsAvailable(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    bool available = se_is_available();
    return Napi::Boolean::New(env, available);
}

Napi::Object GenerateKeyPair(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected string access control").ThrowAsJavaScriptException();
        return Napi::Object::New(env);
    }
    
    std::string accessControl = info[0].As<Napi::String>();
    
    unsigned char* publicKey = nullptr;
    int publicKeyLength = 0;
    unsigned char* privateKey = nullptr;
    int privateKeyLength = 0;
    char* error = nullptr;
    
    bool success = se_generate_key_pair(
        accessControl.c_str(),
        &publicKey,
        &publicKeyLength,
        &privateKey,
        &privateKeyLength,
        &error
    );
    
    if (!success) {
        SwiftError errorWrapper(error);
        std::string errorMsg = error ? std::string(error) : "Unknown error";
        Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
        return Napi::Object::New(env);
    }
    
    SwiftBuffer publicKeyBuffer(publicKey);
    SwiftBuffer privateKeyBuffer(privateKey);
    
    Napi::Object result = Napi::Object::New(env);
    result.Set("publicKey", Napi::Buffer<unsigned char>::Copy(env, publicKey, publicKeyLength));
    result.Set("privateKey", Napi::Buffer<unsigned char>::Copy(env, privateKey, privateKeyLength));
    
    return result;
}

Napi::Buffer<unsigned char> Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Expected two buffers (data, publicKey)").ThrowAsJavaScriptException();
        return Napi::Buffer<unsigned char>::New(env, 0);
    }
    
    Napi::Buffer<unsigned char> dataBuffer = info[0].As<Napi::Buffer<unsigned char>>();
    Napi::Buffer<unsigned char> publicKeyBuffer = info[1].As<Napi::Buffer<unsigned char>>();
    
    unsigned char* ciphertext = nullptr;
    int ciphertextLength = 0;
    char* error = nullptr;
    
    bool success = se_encrypt(
        dataBuffer.Data(),
        dataBuffer.Length(),
        publicKeyBuffer.Data(),
        publicKeyBuffer.Length(),
        &ciphertext,
        &ciphertextLength,
        &error
    );
    
    if (!success) {
        SwiftError errorWrapper(error);
        std::string errorMsg = error ? std::string(error) : "Unknown error";
        Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
        return Napi::Buffer<unsigned char>::New(env, 0);
    }
    
    SwiftBuffer ciphertextBuffer(ciphertext);
    return Napi::Buffer<unsigned char>::Copy(env, ciphertext, ciphertextLength);
}

Napi::Buffer<unsigned char> Decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Expected two buffers (ciphertext, privateKey)").ThrowAsJavaScriptException();
        return Napi::Buffer<unsigned char>::New(env, 0);
    }
    
    Napi::Buffer<unsigned char> ciphertextBuffer = info[0].As<Napi::Buffer<unsigned char>>();
    Napi::Buffer<unsigned char> privateKeyBuffer = info[1].As<Napi::Buffer<unsigned char>>();
    
    unsigned char* plaintext = nullptr;
    int plaintextLength = 0;
    char* error = nullptr;
    
    bool success = se_decrypt(
        ciphertextBuffer.Data(),
        ciphertextBuffer.Length(),
        privateKeyBuffer.Data(),
        privateKeyBuffer.Length(),
        &plaintext,
        &plaintextLength,
        &error
    );
    
    if (!success) {
        SwiftError errorWrapper(error);
        std::string errorMsg = error ? std::string(error) : "Unknown error";
        Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
        return Napi::Buffer<unsigned char>::New(env, 0);
    }
    
    SwiftBuffer plaintextBuffer(plaintext);
    return Napi::Buffer<unsigned char>::Copy(env, plaintext, plaintextLength);
}

Napi::Buffer<unsigned char> GetPublicKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    std::cout << "🔍 GetPublicKey: Starting function" << std::endl;
    
    if (info.Length() < 1 || !info[0].IsBuffer()) {
        std::cout << "❌ GetPublicKey: Invalid arguments" << std::endl;
        Napi::TypeError::New(env, "Expected buffer (privateKey)").ThrowAsJavaScriptException();
        return Napi::Buffer<unsigned char>::New(env, 0);
    }
    
    std::cout << "🔍 GetPublicKey: Getting private key buffer" << std::endl;
    Napi::Buffer<unsigned char> privateKeyBuffer = info[0].As<Napi::Buffer<unsigned char>>();
    
    std::cout << "🔍 GetPublicKey: Private key buffer length: " << privateKeyBuffer.Length() << std::endl;
    
    unsigned char* publicKey = nullptr;
    int publicKeyLength = 0;
    char* error = nullptr;
    
    std::cout << "🔍 GetPublicKey: About to call se_get_public_key" << std::endl;
    
    bool success = se_get_public_key(
        privateKeyBuffer.Data(),
        privateKeyBuffer.Length(),
        &publicKey,
        &publicKeyLength,
        &error
    );
    
    std::cout << "🔍 GetPublicKey: se_get_public_key returned: " << (success ? "success" : "failure") << std::endl;
    
    if (!success) {
        std::cout << "❌ GetPublicKey: Error from Swift: " << (error ? error : "unknown") << std::endl;
        SwiftError errorWrapper(error);
        std::string errorMsg = error ? std::string(error) : "Unknown error";
        Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
        return Napi::Buffer<unsigned char>::New(env, 0);
    }
    
    std::cout << "🔍 GetPublicKey: Public key length: " << publicKeyLength << std::endl;
    std::cout << "🔍 GetPublicKey: Creating return buffer" << std::endl;
    
    SwiftBuffer publicKeyBuffer(publicKey);
    auto result = Napi::Buffer<unsigned char>::Copy(env, publicKey, publicKeyLength);
    
    std::cout << "🔍 GetPublicKey: Function completed successfully" << std::endl;
    
    return result;
}

Napi::Boolean DeleteKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected buffer (privateKey)").ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    Napi::Buffer<unsigned char> privateKeyBuffer = info[0].As<Napi::Buffer<unsigned char>>();
    
    char* error = nullptr;
    
    bool success = se_delete_key(
        privateKeyBuffer.Data(),
        privateKeyBuffer.Length(),
        &error
    );
    
    if (!success) {
        SwiftError errorWrapper(error);
        std::string errorMsg = error ? std::string(error) : "Unknown error";
        Napi::Error::New(env, errorMsg).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }
    
    return Napi::Boolean::New(env, true);
}

Napi::Boolean TestCryptoKitBasic(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    bool success = se_test_cryptokit_basic();
    return Napi::Boolean::New(env, success);
}

// Module initialization
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("isAvailable", Napi::Function::New(env, IsAvailable));
    exports.Set("generateKeyPair", Napi::Function::New(env, GenerateKeyPair));
    exports.Set("encrypt", Napi::Function::New(env, Encrypt));
    exports.Set("decrypt", Napi::Function::New(env, Decrypt));
    exports.Set("getPublicKey", Napi::Function::New(env, GetPublicKey));
    exports.Set("deleteKey", Napi::Function::New(env, DeleteKey));
    exports.Set("testCryptoKitBasic", Napi::Function::New(env, TestCryptoKitBasic));
    
    return exports;
}

NODE_API_MODULE(secure_enclave_native, Init) 