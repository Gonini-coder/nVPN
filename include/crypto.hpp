#pragma once

#include "nvpn_protocol.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <array>
#include <vector>
#include <string>

namespace nvpn {

// Key derivation using HKDF
class KeyDerivation {
public:
    static std::vector<uint8_t> derive_key(
        const std::vector<uint8_t>& shared_secret,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info,
        size_t key_length
    );
};

// X25519 key exchange
class X25519KeyExchange {
public:
    X25519KeyExchange();
    ~X25519KeyExchange();

    std::vector<uint8_t> generate_keypair();
    std::vector<uint8_t> get_public_key() const;
    std::vector<uint8_t> compute_shared_secret(const std::vector<uint8_t>& peer_public);

private:
    EVP_PKEY* keypair_;
    std::vector<uint8_t> public_key_;
};

// AES-256-GCM encryption
class AES256GCM {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

    AES256GCM(const std::array<uint8_t, KEY_SIZE>& key);
    
    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& associated_data = {}
    );
    
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& associated_data = {}
    );

private:
    std::array<uint8_t, KEY_SIZE> key_;
    uint64_t nonce_counter_;
    
    std::vector<uint8_t> generate_nonce();
};

// XChaCha20-Poly1305 encryption (alternative)
class XChaCha20Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;  // OpenSSL uses 12 bytes for ChaCha20-Poly1305
    static constexpr size_t TAG_SIZE = 16;

    XChaCha20Poly1305(const std::array<uint8_t, KEY_SIZE>& key);
    
    std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& associated_data = {}
    );
    
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& associated_data = {}
    );

private:
    std::array<uint8_t, KEY_SIZE> key_;
    uint64_t nonce_counter_;
    
    std::vector<uint8_t> generate_nonce();
};

// Random number generation
class CryptoRandom {
public:
    static std::vector<uint8_t> generate_bytes(size_t length);
    static uint32_t generate_uint32();
    static uint64_t generate_uint64();
};

// Certificate pinning (for fake TLS)
class CertificateManager {
public:
    bool load_certificate(const std::string& cert_path);
    bool load_private_key(const std::string& key_path);
    
    std::vector<uint8_t> get_certificate_data() const;
    bool verify_certificate(const std::vector<uint8_t>& cert_data);
    
    std::vector<uint8_t> sign_data(const std::vector<uint8_t>& data);
    bool verify_signature(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);

private:
    std::vector<uint8_t> certificate_data_;
    EVP_PKEY* private_key_;
};

} // namespace nvpn