#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace pvac;
namespace fs = std::filesystem;

// ==========================================
// Copy IO Helpers from bounty3_test.cpp
// ==========================================

namespace Magic {
constexpr uint32_t CT = 0x66699666;
constexpr uint32_t SK = 0x66666999;
constexpr uint32_t PK = 0x06660666;
constexpr uint32_t VER = 1;
}

namespace io {
std::ostream& put32(std::ostream& o, uint32_t x) {
    return o.write(reinterpret_cast<const char*>(&x), 4);
}
uint32_t get32(std::istream& i) {
    uint32_t x = 0;
    i.read(reinterpret_cast<char*>(&x), 4);
    return x;
}
uint64_t get64(std::istream& i) {
    uint64_t x = 0;
    i.read(reinterpret_cast<char*>(&x), 8);
    return x;
}
std::ostream& put64(std::ostream& o, uint64_t x) {
    return o.write(reinterpret_cast<const char*>(&x), 8);
}
std::ostream& putBv(std::ostream& o, const BitVec& b) {
    put32(o, (uint32_t)b.nbits);
    for (size_t i = 0; i < (b.nbits + 63) / 64; ++i)
        put64(o, b.w[i]);
    return o;
}
BitVec getBv(std::istream& i) {
    auto b = BitVec::make((int)get32(i));
    for (size_t j = 0; j < (b.nbits + 63) / 64; ++j)
        b.w[j] = get64(i);
    return b;
}
std::ostream& putFp(std::ostream& o, const Fp& f) {
    put64(o, f.lo);
    return put64(o, f.hi);
}
Fp getFp(std::istream& i) {
    return { get64(i), get64(i) };
}
} // namespace io

namespace ser {
using namespace io;

void putLayer(std::ostream& o, const Layer& L) {
    o.put((uint8_t)L.rule);
    if (L.rule == RRule::BASE) {
        put64(o, L.seed.ztag);
        put64(o, L.seed.nonce.lo);
        put64(o, L.seed.nonce.hi);
    } else if (L.rule == RRule::PROD) {
        put32(o, L.pa);
        put32(o, L.pb);
    } else {
        put64(o, 0); put64(o, 0); put64(o, 0);
    }
}

Layer getLayer(std::istream& i) {
    Layer L{};
    L.rule = (RRule)i.get();
    if (L.rule == RRule::BASE) {
        L.seed.ztag = get64(i);
        L.seed.nonce.lo = get64(i);
        L.seed.nonce.hi = get64(i);
    } else if (L.rule == RRule::PROD) {
        L.pa = get32(i);
        L.pb = get32(i);
    }
    return L;
}

void putEdge(std::ostream& o, const Edge& e) {
    put32(o, e.layer_id);
    o.write(reinterpret_cast<const char*>(&e.idx), 2);
    o.put(e.ch);
    o.put(0);
    putFp(o, e.w);
    putBv(o, e.s);
}

Edge getEdge(std::istream& i) {
    Edge e{};
    e.layer_id = get32(i);
    i.read(reinterpret_cast<char*>(&e.idx), 2);
    e.ch = i.get();
    i.get();
    e.w = getFp(i);
    e.s = getBv(i);
    return e;
}

void putCipher(std::ostream& o, const Cipher& C) {
    put32(o, (uint32_t)C.L.size());
    put32(o, (uint32_t)C.E.size());
    for (const auto& L : C.L) putLayer(o, L);
    for (const auto& e : C.E) putEdge(o, e);
}

Cipher getCipher(std::istream& i) {
    Cipher C;
    auto nL = get32(i), nE = get32(i);
    C.L.resize(nL);
    C.E.resize(nE);
    for (auto& L : C.L) L = getLayer(i);
    for (auto& e : C.E) e = getEdge(i);
    return C;
}
} // namespace ser

std::vector<Cipher> loadCts(const std::string& path) {
    std::ifstream i(path, std::ios::binary);
    if (io::get32(i) != Magic::CT || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad ct");
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
}

SecKey loadSk(const std::string& path) {
    std::ifstream i(path, std::ios::binary);
    if (io::get32(i) != Magic::SK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad sk");
    SecKey sk;
    for (int j = 0; j < 4; ++j) sk.prf_k[j] = io::get64(i);
    sk.lpn_s_bits.resize(io::get64(i));
    for (auto& w : sk.lpn_s_bits) w = io::get64(i);
    return sk;
}

PubKey loadPk(const std::string& path) {
    std::ifstream i(path, std::ios::binary);
    if (io::get32(i) != Magic::PK || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad pk");
    PubKey pk;
    pk.prm.m_bits = io::get32(i);
    pk.prm.B = io::get32(i);
    pk.prm.lpn_t = io::get32(i);
    pk.prm.lpn_n = io::get32(i);
    pk.prm.lpn_tau_num = io::get32(i);
    pk.prm.lpn_tau_den = io::get32(i);
    pk.prm.noise_entropy_bits = io::get32(i);
    pk.prm.depth_slope_bits = io::get32(i);
    pk.prm.tuple2_fraction = io::get64(i);
    pk.prm.edge_budget = io::get32(i);
    pk.canon_tag = io::get64(i);
    i.read(reinterpret_cast<char*>(pk.H_digest.data()), 32);
    pk.H.resize(io::get64(i));
    for (auto& h : pk.H) h = io::getBv(i);
    pk.ubk.perm.resize(io::get64(i));
    for (auto& v : pk.ubk.perm) v = io::get32(i);
    pk.ubk.inv.resize(io::get64(i));
    for (auto& v : pk.ubk.inv) v = io::get32(i);
    pk.omega_B = io::getFp(i);
    pk.powg_B.resize(io::get64(i));
    for (auto& f : pk.powg_B) f = io::getFp(i);
    return pk;
}

// ==========================================
// Main Decryption Logic
// ==========================================

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <data_dir>\n";
        return 1;
    }

    std::string dir = argv[1];

    try {
        std::cout << "[*] Loading Public Key...\n";
        auto pk = loadPk(dir + "/pk.bin");

        std::cout << "[*] Loading Secret Key...\n";
        auto sk = loadSk(dir + "/sk.bin");

        std::cout << "[*] Loading Ciphertext...\n";
        auto cts = loadCts(dir + "/seed.ct");

        std::cout << "[*] Decrypting...\n";
        // The dec_text function is part of the pvac library
        auto recovered = dec_text(pk, sk, cts);

        std::cout << "\n========================================\n";
        std::cout << "RECOVERED SEED:\n";
        std::cout << recovered << "\n";
        std::cout << "========================================\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
