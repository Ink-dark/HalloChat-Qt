#ifndef CRYPTOSERVICE_H
#define CRYPTOSERVICE_H

#include <QByteArray>
#include <QString>

class CryptoService {
public:
    // 启用低功耗模式（针对ARM Cortex-M0+等设备）
    static void enableLowPowerMode(bool enable);
    
    // 使用CHACHA20-Poly1305加密消息
    // 返回值：加密后的数据流（包含nonce和认证标签）
    static QByteArray encryptMessage(const QString& plaintext, const QByteArray& key);
};

#endif // CRYPTOSERVICE_H