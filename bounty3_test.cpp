// save as: tests/encrypt_custom.cpp
#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <iostream>
#include <fstream>
#include <string>

using namespace pvac;

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <pk_path> <plaintext> <output.ct>\n";
        return 1;
    }

    std::string pk_path = argv[1];
    std::string plaintext = argv[2];
    std::string out_path = argv[3];

    auto pk = PublicKey::load(pk_path);
    auto ct = pk.encrypt(plaintext); // assumes pvac supports string encryption
    ct.save(out_path);

    return 0;
}
