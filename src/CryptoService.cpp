#include "CryptoService.h"
#include <QByteArray>
#include <QRandomGenerator>
#include <QCryptographicHash>
#include <QDataStream>

// XTEA算法实现 (128位密钥, 64位块)
namespace XTEA {
    const int ROUNDS = 32;
    const uint32_t DELTA = 0x9E3779B9;

    void encrypt(uint32_t v[2], const uint32_t k[4]) {
        uint32_t sum = 0;
        for (int i = 0; i < ROUNDS; i++) {
            v[0] += ((v[1] << 4 ^ v[1] >> 5) + v[1]) ^ (sum + k[sum & 3]);
            sum += DELTA;
            v[1] += ((v[0] << 4 ^ v[0] >> 5) + v[0]) ^ (sum + k[sum >> 11 & 3]);
        }
    }

    void decrypt(uint32_t v[2], const uint32_t k[4]) {
        uint32_t sum = DELTA * ROUNDS;
        for (int i = 0; i < ROUNDS; i++) {
            v[1] -= ((v[0] << 4 ^ v[0] >> 5) + v[0]) ^ (sum + k[sum >> 11 & 3]);
            sum -= DELTA;
            v[0] -= ((v[1] << 4 ^ v[1] >> 5) + v[1]) ^ (sum + k[sum & 3]);
        }
    }
}

// ChaCha20算法实现 (256位密钥, 96位nonce)
namespace ChaCha20 {
    void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }

    QByteArray encrypt(const QByteArray &data, const QByteArray &key, const QByteArray &nonce) {
        QByteArray result = data;
        uint32_t state[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            *reinterpret_cast<const uint32_t*>(key.data()),
            *reinterpret_cast<const uint32_t*>(key.data()+4),
            *reinterpret_cast<const uint32_t*>(key.data()+8),
            *reinterpret_cast<const uint32_t*>(key.data()+12),
            *reinterpret_cast<const uint32_t*>(key.data()+16),
            *reinterpret_cast<const uint32_t*>(key.data()+20),
            *reinterpret_cast<const uint32_t*>(key.data()+24),
            *reinterpret_cast<const uint32_t*>(key.data()+28),
            0, // counter
            *reinterpret_cast<const uint32_t*>(nonce.data()),
            *reinterpret_cast<const uint32_t*>(nonce.data()+4),
            *reinterpret_cast<const uint32_t*>(nonce.data()+8)
        };

        uint32_t keystream[16];
        int dataSize = data.size();
        int blocks = (dataSize + 63) / 64;

        for (int b = 0; b < blocks; b++) {
            memcpy(keystream, state, 64);
            for (int i = 0; i < 10; i++) {
                quarterRound(keystream[0], keystream[4], keystream[8], keystream[12]);
                quarterRound(keystream[1], keystream[5], keystream[9], keystream[13]);
                quarterRound(keystream[2], keystream[6], keystream[10], keystream[14]);
                quarterRound(keystream[3], keystream[7], keystream[11], keystream[15]);
                quarterRound(keystream[0], keystream[5], keystream[10], keystream[15]);
                quarterRound(keystream[1], keystream[6], keystream[11], keystream[12]);
                quarterRound(keystream[2], keystream[7], keystream[8], keystream[13]);
                quarterRound(keystream[3], keystream[4], keystream[9], keystream[14]);
            }

            for (int i = 0; i < 16; i++) keystream[i] += state[i];
            state[12]++;

            int bytesToProcess = qMin(64, dataSize - b*64);
            for (int i = 0; i < bytesToProcess; i++) {
                result[b*64 + i] ^= reinterpret_cast<uint8_t*>(keystream)[i];
            }
        }
        return result;
    }
}

// AES-GCM简化实现 (256位密钥)
namespace AESGCM {
    QByteArray encrypt(const QByteArray &data, const QByteArray &key) {
        // 实际实现应使用标准AES-GCM算法
        QByteArray nonce(12, 0);
        QRandomGenerator::system()->generate(nonce.data(), nonce.size());
        QByteArray ciphertext = data;
        // 此处为简化实现，实际项目中应使用加密库
        for (int i = 0; i < ciphertext.size(); i++) {
            ciphertext[i] ^= key[i % key.size()];
        }
        QByteArray tag = QCryptographicHash::hash(nonce + ciphertext, QCryptographicHash::Sha256).left(16);
        return nonce + ciphertext + tag;
    }

    QByteArray decrypt(const QByteArray &data, const QByteArray &key) {
        if (data.size() < 28) return QByteArray(); // 12字节nonce + 16字节tag
        QByteArray nonce = data.left(12);
        QByteArray tag = data.right(16);
        QByteArray ciphertext = data.mid(12, data.size() - 28);
        QByteArray plaintext = ciphertext;
        // 此处为简化实现，实际项目中应使用加密库
        for (int i = 0; i < plaintext.size(); i++) {
            plaintext[i] ^= key[i % key.size()];
        }
        // 验证标签
        QByteArray computedTag = QCryptographicHash::hash(nonce + ciphertext, QCryptographicHash::Sha256).left(16);
        if (computedTag != tag) return QByteArray();
        return plaintext;
    }
}

static bool lowPowerMode = false;

void CryptoService::enableLowPowerMode(bool enable) {
    lowPowerMode = enable;
}

QByteArray CryptoService::xteaEncrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() != 16) return QByteArray(); // XTEA需要128位密钥
    QByteArray paddedData = data;
    // PKCS#7填充
    int padding = 8 - (paddedData.size() % 8);
    paddedData.append(padding, padding);

    QByteArray result;
    uint32_t k[4];
    QDataStream keyStream(key);
    keyStream >> k[0] >> k[1] >> k[2] >> k[3];

    for (int i = 0; i < paddedData.size(); i += 8) {
        uint32_t v[2];
        QDataStream dataStream(paddedData.mid(i, 8));
        dataStream >> v[0] >> v[1];
        XTEA::encrypt(v, k);
        result.append(reinterpret_cast<const char*>(v), 8);
    }
    return result;
}

QByteArray CryptoService::xteaDecrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() != 16 || data.size() % 8 != 0) return QByteArray();
    QByteArray result;
    uint32_t k[4];
    QDataStream keyStream(key);
    keyStream >> k[0] >> k[1] >> k[2] >> k[3];

    for (int i = 0; i < data.size(); i += 8) {
        uint32_t v[2];
        memcpy(v, data.constData() + i, 8);
        XTEA::decrypt(v, k);
        result.append(reinterpret_cast<const char*>(v), 8);
    }
    // 移除PKCS#7填充
    if (result.isEmpty()) return result;
    int padding = static_cast<unsigned char>(result.last());
    if (padding > 8) return QByteArray();
    return result.left(result.size() - padding);
}

QByteArray CryptoService::chacha20Encrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() != 32) return QByteArray(); // ChaCha20需要256位密钥
    QByteArray nonce(12, 0);
    QRandomGenerator::system()->generate(nonce.data(), nonce.size());
    QByteArray ciphertext = ChaCha20::encrypt(data, key, nonce);
    return nonce + ciphertext;
}

QByteArray CryptoService::chacha20Decrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() != 32 || data.size() < 12) return QByteArray();
    QByteArray nonce = data.left(12);
    QByteArray ciphertext = data.mid(12);
    return ChaCha20::encrypt(ciphertext, key, nonce); // ChaCha20加密解密使用相同操作
}

QByteArray CryptoService::aesGcmEncrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() != 32) return QByteArray(); // AES-256需要256位密钥
    return AESGCM::encrypt(data, key);
}

QByteArray CryptoService::aesGcmDecrypt(const QByteArray &data, const QByteArray &key) {
    if (key.size() != 32) return QByteArray(); // AES-256需要256位密钥
    return AESGCM::decrypt(data, key);
}