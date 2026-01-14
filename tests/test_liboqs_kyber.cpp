#include <iostream>
#include <vector>
#include <cstring>
#include <oqs/oqs.h>

void print_hex(const char* label, const uint8_t* data, const size_t len, const size_t max_show = 16) {
    std::cout << label << " (" << len << " bytes): ";
    for (size_t i = 0; i < std::min(len, max_show); ++i) {
        printf("%02x", data[i]);
    }
    if (len > max_show) {
        std::cout << "...";
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "=== liboqs Kyber-768 Test ===" << std::endl;
    std::cout << "liboqs version: 0.15.0" << std::endl << std::endl;

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (kem == nullptr) {
        std::cerr << "ERROR: Failed to create Kyber-768 KEM instance" << std::endl;
        return 1;
    }

    std::cout << "KEM Algorithm: " << kem->method_name << std::endl;
    std::cout << "Public Key Size: " << kem->length_public_key << " bytes" << std::endl;
    std::cout << "Secret Key Size: " << kem->length_secret_key << " bytes" << std::endl;
    std::cout << "Ciphertext Size: " << kem->length_ciphertext << " bytes" << std::endl;
    std::cout << "Shared Secret Size: " << kem->length_shared_secret << " bytes" << std::endl;
    std::cout << std::endl;

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_sender(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_receiver(kem->length_shared_secret);

    std::cout << "[TEST 1] Key Generation" << std::endl;
    OQS_STATUS status = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        std::cerr << "ERROR: Key generation failed" << std::endl;
        OQS_KEM_free(kem);
        return 1;
    }
    std::cout << "✓ Key generation successful" << std::endl;
    print_hex("  Public Key", public_key.data(), public_key.size());
    print_hex("  Secret Key", secret_key.data(), secret_key.size());
    std::cout << std::endl;

    std::cout << "[TEST 2] Encapsulation" << std::endl;
    status = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(), public_key.data());
    if (status != OQS_SUCCESS) {
        std::cerr << "ERROR: Encapsulation failed" << std::endl;
        OQS_KEM_free(kem);
        return 1;
    }
    std::cout << "✓ Encapsulation successful" << std::endl;
    print_hex("  Ciphertext", ciphertext.data(), ciphertext.size());
    print_hex("  Shared Secret (Sender)", shared_secret_sender.data(), shared_secret_sender.size());
    std::cout << std::endl;

    std::cout << "[TEST 3] Decapsulation" << std::endl;
    status = OQS_KEM_decaps(kem, shared_secret_receiver.data(), ciphertext.data(), secret_key.data());
    if (status != OQS_SUCCESS) {
        std::cerr << "ERROR: Decapsulation failed" << std::endl;
        OQS_KEM_free(kem);
        return 1;
    }
    std::cout << "✓ Decapsulation successful" << std::endl;
    print_hex("  Shared Secret (Receiver)", shared_secret_receiver.data(), shared_secret_receiver.size());
    std::cout << std::endl;

    std::cout << "[TEST 4] Shared Secret Agreement" << std::endl;
    if (std::memcmp(shared_secret_sender.data(), shared_secret_receiver.data(),
                    shared_secret_sender.size()) == 0) {
        std::cout << "✓ Shared secrets match! Kyber-768 working correctly." << std::endl;
    } else {
        std::cerr << "ERROR: Shared secrets DO NOT match!" << std::endl;
        OQS_KEM_free(kem);
        return 1;
    }
    std::cout << std::endl;

    std::cout << "[TEST 5] Size Verification (FIPS 203 Kyber-768)" << std::endl;
    bool sizes_correct = true;
    if (kem->length_public_key != 1184) {
        std::cerr << "ERROR: Public key size mismatch (expected 1184, got "
                  << kem->length_public_key << ")" << std::endl;
        sizes_correct = false;
    }
    if (kem->length_secret_key != 2400) {
        std::cerr << "ERROR: Secret key size mismatch (expected 2400, got "
                  << kem->length_secret_key << ")" << std::endl;
        sizes_correct = false;
    }
    if (kem->length_ciphertext != 1088) {
        std::cerr << "ERROR: Ciphertext size mismatch (expected 1088, got "
                  << kem->length_ciphertext << ")" << std::endl;
        sizes_correct = false;
    }
    if (kem->length_shared_secret != 32) {
        std::cerr << "ERROR: Shared secret size mismatch (expected 32, got "
                  << kem->length_shared_secret << ")" << std::endl;
        sizes_correct = false;
    }

    if (sizes_correct) {
        std::cout << "✓ All sizes match FIPS 203 specification" << std::endl;
    } else {
        OQS_KEM_free(kem);
        return 1;
    }

    OQS_KEM_free(kem);

    std::cout << "\n=== ALL TESTS PASSED ===" << std::endl;
    std::cout << "liboqs Kyber-768 is working correctly and ready for integration." << std::endl;

    return 0;
}
