#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <random>
#include <algorithm>
#include <cstring>
#include <stdint.h>
#include <fstream>
#include <Windows.h>

#pragma warning (disable: 26495) 
using namespace std;

class SHA256 {
public:
    static std::vector<uint8_t> hash(const std::string& input) {
        SHA256 ctx;
        ctx.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        ctx.finalize();
        return ctx.digest;
    }
private:
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
    std::vector<uint8_t> digest;
    static uint32_t rotr(uint32_t x, uint32_t n) {return (x >> n) | (x << (32 - n));}
    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {return (e & f) ^ (~e & g);}
    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {return (a & b) ^ (a & c) ^ (b & c);}
    static uint32_t sig0(uint32_t x) {return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);}
    static uint32_t sig1(uint32_t x) {return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);}
    static uint32_t ep0(uint32_t x) {return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);}
    static uint32_t ep1(uint32_t x) {return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);}
    SHA256() : datalen(0), bitlen(0), digest(32) {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }
    void update(const uint8_t* dataIn, size_t len) {
        for (size_t i = 0; i < len; i++) {
            data[datalen] = dataIn[i];
            datalen++;
            if (datalen == 64) {
                transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }
    void finalize() {
        size_t i = datalen;
        if (datalen < 56) {data[i++] = 0x80;while (i < 56) data[i++] = 0x00;}
        else {
            data[i++] = 0x80;
            while (i < 64) data[i++] = 0x00;
            transform();
            std::memset(data, 0, 56);
        }
        bitlen += datalen * 8;
        for (int j = 7; j >= 0; j--)
            data[56 + (7 - j)] = (bitlen >> (j * 8)) & 0xff;
        transform();
        for (int j = 0; j < 8; j++) {
            digest[j * 4] = (state[j] >> 24) & 0xff;
            digest[j * 4 + 1] = (state[j] >> 16) & 0xff;
            digest[j * 4 + 2] = (state[j] >> 8) & 0xff;
            digest[j * 4 + 3] = state[j] & 0xff;
        }
    }
    void transform() {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t m[64];
        for (int i = 0; i < 16; i++) m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | (data[i * 4 + 3]);
        for (int i = 16; i < 64; i++) m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h + ep1(e) + choose(e, f, g) + k[i] + m[i];
            uint32_t t2 = ep0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
};
static std::string Hexa(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t c : data) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}
static std::vector<uint8_t> IntNonSigne(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        uint8_t b = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        out.push_back(b);
    }
    return out;
}
class MCE20 {
public:
    MCE20(const std::vector<uint8_t>& clef, const std::vector<uint8_t>& mce, uint32_t compteur = 1) {
        std::memset(etat, 0, sizeof(etat));
        etat[0] = 0x61707865;
        etat[1] = 0x3320646e;
        etat[2] = 0x79622d32;
        etat[3] = 0x6b206574;
        for (int i = 0; i < 8; ++i) {
            etat[4 + i] =
                clef[4 * i] |
                (clef[4 * i + 1] << 8) |
                (clef[4 * i + 2] << 16) |
                (clef[4 * i + 3] << 24);
        }
        etat[12] = compteur;
        for (int i = 0; i < 3; ++i) {etat[13 + i] =mce[4 * i] |(mce[4 * i + 1] << 8) |(mce[4 * i + 2] << 16) |(mce[4 * i + 3] << 24);}
    }
    void crypt(uint8_t* data, size_t len) {
        uint8_t block[64];
        size_t offset = 0;
        while (offset < len) {
            generateBlock(block);
            size_t blockSize = min(len - offset, (size_t)64);
            for (size_t i = 0; i < blockSize; ++i)data[offset + i] ^= block[i];
            offset += blockSize;
            etat[12]++; 
        }
    }
private:
    uint32_t etat[16];
    static uint32_t rotl(uint32_t v, int c) {return (v << c) | (v >> (32 - c));}
    static void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }
    void generateBlock(uint8_t out[64]) const {
        uint32_t x[16];
        std::memcpy(x, etat, sizeof(x));

        for (int i = 0; i < 10; ++i) {
            quarterRound(x[0], x[4], x[8], x[12]);
            quarterRound(x[1], x[5], x[9], x[13]);
            quarterRound(x[2], x[6], x[10], x[14]);
            quarterRound(x[3], x[7], x[11], x[15]);
            quarterRound(x[0], x[5], x[10], x[15]);
            quarterRound(x[1], x[6], x[11], x[12]);
            quarterRound(x[2], x[7], x[8], x[13]);
            quarterRound(x[3], x[4], x[9], x[14]);
        }
        for (int i = 0; i < 16; ++i)  x[i] += etat[i];
        for (int i = 0; i < 16; ++i) {
            out[4 * i + 0] = x[i] & 0xff;
            out[4 * i + 1] = (x[i] >> 8) & 0xff;
            out[4 * i + 2] = (x[i] >> 16) & 0xff;
            out[4 * i + 3] = (x[i] >> 24) & 0xff;
        }
    }
};
class LoginEncrypte {
public:
    std::string nom, passe;
    LoginEncrypte(const std::string& username,const std::string& password,const std::string& filePath): filePath(filePath){
        salt.resize(16);
        nom = username;
        passe = password;
        std::random_device rd;
        for (auto& b : salt) b = rd() & 0xFF;
        std::string material = username + password + Hexa(salt);
        key = SHA256::hash(material);
        nonce.resize(12);
        for (auto& b : nonce) b = rd() & 0xFF;
        out.open(filePath, std::ios::app);
    }
    ~LoginEncrypte() {if (out.is_open()) out.close();}
    void log(const std::string& msg) {
        std::vector<uint8_t> data(msg.begin(), msg.end());
        MCE20 mce20a(key, nonce, 1);
        mce20a.crypt(data.data(), data.size());
        printf("\n\tSalt: %s\n\tResultat: %s\n", Hexa(salt).c_str(), Hexa(data).c_str());
        if (out.is_open()) {out  << "\n\r"<< Hexa(salt) << "|"<< Hexa(nonce) << "|"<< Hexa(data);}
    }
    std::string DecrypteLigne(const std::string& line,const std::string& username,const std::string& password)
    {
        auto p1 = line.find('|');
        auto p2 = line.find('|', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) return "";
        std::string saltHex = line.substr(0, p1);
        std::string nonceHex = line.substr(p1 + 1, p2 - p1 - 1);
        std::string cipherHex = line.substr(p2 + 1);
        auto saltLocal = IntNonSigne(saltHex);
        auto nonceLocal = IntNonSigne(nonceHex);
        auto cipher = IntNonSigne(cipherHex);
        std::string material = username + password + saltHex;
        auto keyLocal = SHA256::hash(material);
        MCE20 chacha(keyLocal, nonceLocal, 1);
        chacha.crypt(cipher.data(), cipher.size());
        return std::string(cipher.begin(), cipher.end());
    }
private:
    std::string filePath;
    std::ofstream out;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> key;
};
static void Cls() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD count;
    DWORD cellCount;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi))return;
    cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    FillConsoleOutputCharacter(hConsole, ' ', cellCount, { 0, 0 }, &count);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, cellCount, { 0, 0 }, &count);
    SetConsoleCursorPosition(hConsole, { 0, 0 });
}
static void ChangerCouleur(char* source,char* cible,WORD couleur) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    cout << cible << 
    SetConsoleTextAttribute(hConsole, couleur);
    cout << cible << endl;
}
static void ChangerCouleur(WORD couleur) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), couleur); }
int main() {
    SetConsoleTitle(L"Generateur Login SSL-SHA256");
    Cls();
    ChangerCouleur(15);
    std::string nomUtilisateur, motPasse;
    printf("Nom d'utilisateur : ");ChangerCouleur(14);
    std::getline(std::cin, nomUtilisateur);ChangerCouleur(15);
    std::cout << "Mot de passe : ";ChangerCouleur(14);
    std::getline(std::cin, motPasse);ChangerCouleur(15);
    LoginEncrypte logger(nomUtilisateur, motPasse, "logs_chiffres.txt");
    logger.log("Application start");
    logger.log("Utilisateur " + nomUtilisateur + " connecte.");
    logger.log("Une erreur simulee pour le test.");
    std::cout << "\nLogs chiffres ecrits dans logs_chiffres.txt\n";
    std::ifstream in("logs_chiffres.txt");
    std::string line, lastLine;
    while (std::getline(in, line)) { if (!line.empty()) lastLine = line;}
    in.close();
    if (!lastLine.empty()) {
        Cls();
        std::string sha256 = logger.DecrypteLigne(lastLine, nomUtilisateur, motPasse);
        ChangerCouleur(15); cout << "Nom d'utilisateur: ";
        ChangerCouleur(10); cout <<nomUtilisateur <<endl;
        ChangerCouleur(15); cout << "Mot de passe: ";
        ChangerCouleur(10); cout << motPasse<<endl;
        ChangerCouleur(15); cout << "SHA256: ";
        ChangerCouleur(10); cout << sha256<<endl;
        ChangerCouleur(12); cout << "Appuyer sur entree pour quitter" <<endl;
    }
    return getchar();
}
