#include "AuthManager.h"
#include <QDateTime>
#include <QCryptographicHash>
#include <QJsonObject>
#include <QJsonDocument>
#include <QFile>
#include <QDebug>

// 使用开发环境密钥（生产环境应从安全存储加载）
AuthManager::AuthManager(QObject* parent) : QObject(parent) {
    // 尝试从安全存储加载密钥，失败则使用默认开发密钥
    loadSecretKey();
    if (secretKey.isEmpty()) {
        secretKey = QCryptographicHash::hash(
            "HalloChatSecret!@#2023",
            QCryptographicHash::Sha256
        );
    }
}

void AuthManager::loadProductionKey()
{
    // 生产环境从安全路径加载密钥
    QFile keyFile("/run/secrets/jwt_key");
    if (keyFile.open(QIODevice::ReadOnly)) {
        secretKey = keyFile.readAll();
        keyFile.close();
        qInfo() << "成功加载生产环境密钥";
    } else {
        qWarning() << "使用开发环境密钥! 生产环境需要配置安全密钥";
        secretKey = QCryptographicHash::hash(
            "HalloChatSecret!@#2023",
            QCryptographicHash::Sha256
        );
    }
}

bool AuthManager::secureCompare(const QString& a, const QString& b)
{
    if (a.length() != b.length()) return false;
    int result = 0;
    for (int i = 0; i < a.length(); ++i) {
        result |= a[i].unicode() ^ b[i].unicode();
    }
    return result == 0;

QString AuthManager::generateToken(const QString& userId) {
    QJsonObject header {
        {"alg", algorithm},
        {"typ", "JWT"}
    };
    
    QJsonObject payload {
        {"sub", userId},
        {"iat", QDateTime::currentSecsSinceEpoch()},
        {"exp", QDateTime::currentSecsSinceEpoch() + 3600} // 1小时有效期
    };
    
    // Base64编码头部和载荷（URL安全模式）
    QByteArray headerBytes = QJsonDocument(header).toJson(QJsonDocument::Compact);
    QByteArray payloadBytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    QString headerBase64 = headerBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QString payloadBase64 = payloadBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    
    // 生成签名
    QByteArray signatureInput = (headerBase64 + "." + payloadBase64).toUtf8();
    QByteArray signature = QCryptographicHash::hash(signatureInput, QCryptographicHash::Sha256);
    QString signatureBase64 = signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    
    return headerBase64 + "." + payloadBase64 + "." + signatureBase64;
}

bool AuthManager::validateToken(const QString& token) {
    QStringList parts = token.split(".");
    if (parts.size() != 3) return false;
    
    // 验证签名
    QByteArray signatureInput = (parts[0] + "." + parts[1]).toUtf8();
    QByteArray expectedSignature = QCryptographicHash::hash(signatureInput, QCryptographicHash::Sha256);
    QByteArray actualSignature = QByteArray::fromBase64(parts[2].toUtf8(), QByteArray::Base64UrlEncoding);
    
    // 使用安全比较防止时序攻击
    if (!secureCompare(actualSignature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals),
                       expectedSignature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))) {
        return false;
    }
    
    // 验证过期时间
    QByteArray payloadBytes = QByteArray::fromBase64(parts[1].toUtf8(), QByteArray::Base64UrlEncoding);
    QJsonObject payload = QJsonDocument::fromJson(payloadBytes).object();
    
    qint64 exp = payload["exp"].toDouble();
    qint64 now = QDateTime::currentSecsSinceEpoch();
    
    return exp > now;
}

QString AuthManager::refreshToken(const QString& token) {
    if (!validateToken(token)) return "";
    
    QString userId = getUserIdFromToken(token);
    return generateToken(userId); // 生成新令牌
}

QString AuthManager::getUserIdFromToken(const QString& token) {
    QStringList parts = token.split(".");
    if (parts.size() != 3) return "";
    
    QByteArray payloadBytes = QByteArray::fromBase64(parts[1].toUtf8(), QByteArray::Base64UrlEncoding);
    QJsonObject payload = QJsonDocument::fromJson(payloadBytes).object();
    
    return payload["sub"].toString();
}