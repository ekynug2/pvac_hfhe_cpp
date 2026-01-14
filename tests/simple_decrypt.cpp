#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>

using namespace pvac;
namespace fs = std::filesystem;

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

std::ostream& put64(std::ostream& o, uint64_t x) {
    return o.write(reinterpret_cast<const char*>(&x), 8);
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

}

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
        put64(o, 0);
        put64(o, 0);
        put64(o, 0);
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

}

void saveCts(const std::vector<Cipher>& cts, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::CT);
    io::put32(o, Magic::VER);
    io::put64(o, cts.size());
    for (const auto& c : cts) ser::putCipher(o, c);
}

std::vector<Cipher> loadCts(const std::string& path) {
    std::ifstream i(path, std::ios::binary);
    if (io::get32(i) != Magic::CT || io::get32(i) != Magic::VER)
        throw std::runtime_error("bad ct");
    std::vector<Cipher> cts(io::get64(i));
    for (auto& c : cts) c = ser::getCipher(i);
    return cts;
}

void saveSk(const SecKey& sk, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::SK);
    io::put32(o, Magic::VER);
    for (int j = 0; j < 4; ++j) io::put64(o, sk.prf_k[j]);
    io::put64(o, sk.lpn_s_bits.size());
    for (auto w : sk.lpn_s_bits) io::put64(o, w);
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

void savePk(const PubKey& pk, const std::string& path) {
    std::ofstream o(path, std::ios::binary);
    io::put32(o, Magic::PK);
    io::put32(o, Magic::VER);
    io::put32(o, pk.prm.m_bits);
    io::put32(o, pk.prm.B);
    io::put32(o, pk.prm.lpn_t);
    io::put32(o, pk.prm.lpn_n);
    io::put32(o, pk.prm.lpn_tau_num);
    io::put32(o, pk.prm.lpn_tau_den);
    io::put32(o, (uint32_t)pk.prm.noise_entropy_bits);
    io::put32(o, (uint32_t)pk.prm.depth_slope_bits);
    io::put64(o, pk.prm.tuple2_fraction);
    io::put32(o, pk.prm.edge_budget);
    io::put64(o, pk.canon_tag);
    o.write(reinterpret_cast<const char*>(pk.H_digest.data()), 32);
    io::put64(o, pk.H.size());
    for (const auto& h : pk.H) io::putBv(o, h);
    io::put64(o, pk.ubk.perm.size());
    for (auto v : pk.ubk.perm) io::put32(o, v);
    io::put64(o, pk.ubk.inv.size());
    for (auto v : pk.ubk.inv) io::put32(o, v);
    io::putFp(o, pk.omega_B);
    io::put64(o, pk.powg_B.size());
    for (const auto& f : pk.powg_B) io::putFp(o, f);
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

void saveParams(const Params& p, const std::string& path) {
    std::ofstream o(path);
    o << "{\n"
      << "  \"m_bits\": " << p.m_bits << ",\n"
      << "  \"B\": " << p.B << ",\n"
      << "  \"lpn_t\": " << p.lpn_t << ",\n"
      << "  \"lpn_n\": " << p.lpn_n << ",\n"
      << "  \"lpn_tau_num\": " << p.lpn_tau_num << ",\n"
      << "  \"lpn_tau_den\": " << p.lpn_tau_den << ",\n"
      << "  \"noise_entropy_bits\": " << p.noise_entropy_bits << ",\n"
      << "  \"depth_slope_bits\": " << p.depth_slope_bits << ",\n"
      << "  \"tuple2_fraction\": " << p.tuple2_fraction << ",\n"
      << "  \"edge_budget\": " << p.edge_budget << "\n"
      << "}\n";
}

int main() {
    std::cout << "- simple decrypt -\n";

    // Use the same directory
    const std::string dir = "bounty3_data";

    try {
        // Only Load and Decrypt - Skip Keygen and Encrypt
        
        std::cout << "[*] Loading Keys and Ciphertext...\n";
        
        // Load everything first
        auto pk = loadPk(dir + "/pk.bin");
        auto sk = loadSk(dir + "/sk.bin");
        auto cts = loadCts(dir + "/seed.ct");

        std::cout << "[*] Starting Decryption...\n";
        std::cout << "[!] This may consume significant RAM...\n";

        // Decrypt
        auto dec = dec_text(pk, sk, cts);

        std::cout << "\n========================================\n";
        std::cout << "SUCCESS: Recovered Plaintext\n";
        std::cout << "========================================\n";
        std::cout << dec << "\n";
        std::cout << "========================================\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        
        if (std::string(e.what()) == "std::bad_alloc") {
            std::cerr << "\n[!] MEMORY ERROR: Your system ran out of RAM." << std::endl;
            std::cerr << "[!] Try closing other applications or increasing swap/WSL memory." << std::endl;
        }
        return 1;
    }

    return 0;
}
