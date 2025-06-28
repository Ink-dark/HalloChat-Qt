#ifndef CRYPTOSERVICE_H
#define CRYPTOSERVICE_H

#include <QByteArray>
#include <QString>

class CryptoService {
public:
    // 启用低功耗模式（针对ARM Cortex-M0+等设备）
    static void enableLowPowerMode(bool enable);
    
    // XTEA加密解密（低功耗设备）
    static QByteArray xteaEncrypt(const QByteArray& data, const QByteArray& key);
    static QByteArray xteaDecrypt(const QByteArray& data, const QByteArray& key);
    
    // ChaCha20加密解密（移动设备）
    static QByteArray chacha20Encrypt(const QByteArray& data, const QByteArray& key);
    static QByteArray chacha20Decrypt(const QByteArray& data, const QByteArray& key);
    
    // AES-GCM加密解密（桌面设备）
    static QByteArray aesGcmEncrypt(const QByteArray& data, const QByteArray& key);
    static QByteArray aesGcmDecrypt(const QByteArray& data, const QByteArray& key);
};

#endif // CRYPTOSERVICE_H