#include "CryptoService.h"
#include <QByteArray>
#include <QCryptographicHash>
#include <QRandomGenerator>

// 假设存在ChaCha20和Poly1305实现
class ChaCha20 {
private:
    QByteArray key;
    bool lowPowerMode = false;
public:
    ChaCha20(const QByteArray& k) : key(k) {}
    void setLowPowerMode(bool enable) { lowPowerMode = enable; }
    QByteArray encrypt(const QByteArray& plaintext) {
        // 实际实现应使用标准ChaCha20算法
        QByteArray nonce(12, 0);
        QRandomGenerator::system()->generate(nonce.data(), nonce.size());
        return nonce + QCryptographicHash::hash(plaintext, QCryptographicHash::Sha256);
    }
};

class Poly1305 {
private:
    QByteArray key;
public:
    Poly1305(const QByteArray& k) : key(k) {}
    QByteArray computeMac(const QByteArray& data) {
        // 实际实现应使用标准Poly1305算法
        return QCryptographicHash::hash(data, QCryptographicHash::Sha256).left(16);
    }
};

static bool lowPowerMode = false;

void CryptoService::enableLowPowerMode(bool enable) {
    lowPowerMode = enable;
}

QByteArray CryptoService::encryptMessage(const QString& plaintext, const QByteArray& key) {
    ChaCha20 chacha(key);
    if (lowPowerMode) {
        chacha.setLowPowerMode(true);
    }
    QByteArray ciphertext = chacha.encrypt(plaintext.toUtf8());
    Poly1305 poly(key);
    QByteArray mac = poly.computeMac(ciphertext);
    return ciphertext + mac;
}