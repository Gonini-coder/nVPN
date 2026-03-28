#include "crypto.hpp"
#include <iostream>
#include <string>
#include <algorithm>
#include <fstream>
#include <sstream>

namespace nvpn {

// Key derivation using HKDF
std::vector<uint8_t> KeyDerivation::derive_key(
    const std::vector<uint8_t>& shared_secret,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t key_length) {
    
    std::vector<uint8_t> result(key_length);
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return {};
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    // Set hash function for HKDF
    if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_MD, 0, (void*)EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    // Set salt for HKDF
    if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SET1_ID, salt.size(), (void*)salt.data()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    // Set key for HKDF
    if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SET_MAC_KEY, shared_secret.size(), (void*)shared_secret.data()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    // Add info for HKDF
    if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SET1_ID, info.size(), (void*)info.data()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    size_t out_len = key_length;
    if (EVP_PKEY_derive(ctx, result.data(), &out_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    EVP_PKEY_CTX_free(ctx);
    return result;
}

// X25519 key exchange
X25519KeyExchange::X25519KeyExchange() : keypair_(nullptr) {
}

X25519KeyExchange::~X25519KeyExchange() {
    if (keypair_) {
        EVP_PKEY_free(keypair_);
    }
}

std::vector<uint8_t> X25519KeyExchange::generate_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        return {};
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    if (EVP_PKEY_keygen(ctx, &keypair_) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Extract public key
    size_t pub_len = 0;
    if (EVP_PKEY_get_raw_public_key(keypair_, nullptr, &pub_len) <= 0) {
        return {};
    }
    
    public_key_.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(keypair_, public_key_.data(), &pub_len) <= 0) {
        return {};
    }
    
    return public_key_;
}

std::vector<uint8_t> X25519KeyExchange::get_public_key() const {
    return public_key_;
}

std::vector<uint8_t> X25519KeyExchange::compute_shared_secret(const std::vector<uint8_t>& peer_public) {
    if (!keypair_) {
        return {};
    }
    
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, 
                                                       peer_public.data(), peer_public.size());
    if (!peer_key) {
        return {};
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair_, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer_key);
        return {};
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return {};
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return {};
    }
    
    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return {};
    }
    
    std::vector<uint8_t> shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        return {};
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    
    return shared_secret;
}

// AES-256-GCM implementation
AES256GCM::AES256GCM(const std::array<uint8_t, KEY_SIZE>& key)
    : key_(key)
    , nonce_counter_(0) {
}

std::vector<uint8_t> AES256GCM::generate_nonce() {
    std::vector<uint8_t> nonce(NONCE_SIZE);
    
    // Use counter-based nonce with random prefix
    uint64_t counter = nonce_counter_++;
    memcpy(nonce.data(), &counter, sizeof(counter));
    
    // Fill remaining with random bytes
    std::vector<uint8_t> random_bytes = CryptoRandom::generate_bytes(NONCE_SIZE - sizeof(counter));
    memcpy(nonce.data() + sizeof(counter), random_bytes.data(), random_bytes.size());
    
    return nonce;
}

std::vector<uint8_t> AES256GCM::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& associated_data) {
    
    std::vector<uint8_t> nonce = generate_nonce();
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Add associated data
    if (!associated_data.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx, nullptr, &len, 
                              associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }
    
    // Encrypt plaintext
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine: nonce + ciphertext + tag
    std::vector<uint8_t> result;
    result.reserve(NONCE_SIZE + ciphertext.size() + TAG_SIZE);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::vector<uint8_t> AES256GCM::decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& associated_data) {
    
    if (ciphertext.size() < NONCE_SIZE + TAG_SIZE) {
        return {};
    }
    
    // Extract nonce, ciphertext, and tag
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + NONCE_SIZE);
    std::vector<uint8_t> encrypted(ciphertext.begin() + NONCE_SIZE, 
                                     ciphertext.end() - TAG_SIZE);
    std::vector<uint8_t> tag(ciphertext.end() - TAG_SIZE, ciphertext.end());
    
    std::vector<uint8_t> plaintext(encrypted.size());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Add associated data
    if (!associated_data.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx, nullptr, &len, 
                              associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }
    
    // Decrypt
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                          encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // Authentication failed
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    plaintext.resize(len + final_len);
    return plaintext;
}

// XChaCha20-Poly1305 implementation
XChaCha20Poly1305::XChaCha20Poly1305(const std::array<uint8_t, KEY_SIZE>& key)
    : key_(key)
    , nonce_counter_(0) {
}

std::vector<uint8_t> XChaCha20Poly1305::generate_nonce() {
    std::vector<uint8_t> nonce(NONCE_SIZE);
    
    // Use counter-based nonce with random prefix
    uint64_t counter = nonce_counter_++;
    memcpy(nonce.data(), &counter, sizeof(counter));
    
    std::vector<uint8_t> random_bytes = CryptoRandom::generate_bytes(NONCE_SIZE - sizeof(counter));
    memcpy(nonce.data() + sizeof(counter), random_bytes.data(), random_bytes.size());
    
    return nonce;
}

std::vector<uint8_t> XChaCha20Poly1305::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& associated_data) {
    
    std::vector<uint8_t> nonce = generate_nonce();
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(TAG_SIZE);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }
    
    // Note: OpenSSL 1.1.1+ supports XChaCha20-Poly1305
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Add associated data
    if (!associated_data.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx, nullptr, &len, 
                              associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }
    
    // Encrypt
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                          plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine: nonce + ciphertext + tag
    std::vector<uint8_t> result;
    result.reserve(NONCE_SIZE + ciphertext.size() + TAG_SIZE);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    
    return result;
}

std::vector<uint8_t> XChaCha20Poly1305::decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& associated_data) {
    
    if (ciphertext.size() < NONCE_SIZE + TAG_SIZE) {
        return {};
    }
    
    // Extract nonce, ciphertext, and tag
    std::vector<uint8_t> nonce(ciphertext.begin(), ciphertext.begin() + NONCE_SIZE);
    std::vector<uint8_t> encrypted(ciphertext.begin() + NONCE_SIZE, 
                                     ciphertext.end() - TAG_SIZE);
    std::vector<uint8_t> tag(ciphertext.end() - TAG_SIZE, ciphertext.end());
    
    std::vector<uint8_t> plaintext(encrypted.size());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return {};
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key_.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Add associated data
    if (!associated_data.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx, nullptr, &len, 
                              associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
    }
    
    // Decrypt
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                          encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // Authentication failed
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    plaintext.resize(len + final_len);
    return plaintext;
}

// Random number generation
std::vector<uint8_t> CryptoRandom::generate_bytes(size_t length) {
    std::vector<uint8_t> result(length);
    if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
        return {};
    }
    return result;
}

uint32_t CryptoRandom::generate_uint32() {
    uint32_t result;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result)) != 1) {
        return 0;
    }
    return result;
}

uint64_t CryptoRandom::generate_uint64() {
    uint64_t result;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&result), sizeof(result)) != 1) {
        return 0;
    }
    return result;
}

// CertificateManager implementation
bool CertificateManager::load_certificate(const std::string& cert_path) {
    // Placeholder implementation - in a real implementation, this would load
    // and parse an X.509 certificate from the given file
    std::ifstream file(cert_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Read the file contents
    std::ostringstream buffer;
    buffer << file.rdbuf();
    certificate_data_ = std::vector<uint8_t>(
        buffer.str().begin(), 
        buffer.str().end()
    );
    
    return !certificate_data_.empty();
}

bool CertificateManager::load_private_key(const std::string& key_path) {
    // Placeholder implementation - in a real implementation, this would load
    // and parse a private key from the given file
    std::ifstream file(key_path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // For now, we'll just check if the file exists and is readable
    // A real implementation would use OpenSSL functions to load the key
    return file.good();
}

std::vector<uint8_t> CertificateManager::get_certificate_data() const {
    return certificate_data_;
}

bool CertificateManager::verify_certificate(const std::vector<uint8_t>& cert_data) {
    // Placeholder implementation
    // In a real implementation, this would verify the certificate signature,
    // validity period, etc.
    return !cert_data.empty();
}

std::vector<uint8_t> CertificateManager::sign_data(const std::vector<uint8_t>& data) {
    // Placeholder implementation
    // In a real implementation, this would sign the data using the private key
    return std::vector<uint8_t>();
}

bool CertificateManager::verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature) {
    // Placeholder implementation
    // In a real implementation, this would verify the signature using the public key
    return !data.empty() && !signature.empty();
}

} // namespace nvpn