#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <iostream>
#include <fstream>
#include <string>

// Use full namespace
using namespace pvac;

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public_key.bin> <plaintext_string> <output.ct>\n";
        return 1;
    }

    std::string pk_path = argv[1];
    std::string plaintext = argv[2];
    std::string out_path = argv[3];

    try {
        // Load public key — likely needs explicit type or factory
        auto pk = crypto::load_public_key(pk_path);  // ← common in PVAC
        std::vector<uint8_t> bytes(plaintext.begin(), plaintext.end());
        auto ct = pk.encrypt(bytes);
        ct.save(out_path);
        std::cout << "Encrypted to " << out_path << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
