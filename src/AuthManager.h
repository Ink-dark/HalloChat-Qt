#pragma once
#include <QObject>
#include <QString>

class AuthManager : public QObject {
    Q_OBJECT
public:
    explicit AuthManager(QObject* parent = nullptr);
    
    QString generateToken(const QString& userId);
    bool validateToken(const QString& token);
    QString refreshToken(const QString& token);
    QString getUserIdFromToken(const QString& token);
    
private:
    bool secureCompare(const QString& a, const QString& b);
    void revokeToken(const QString& jti);
    bool isTokenRevoked(const QString& jti);
    
    QByteArray secretKey;
    QString algorithm = "HS256";  // HMAC-SHA256
    QHash<QString, qint64> revokedTokens; // 存储吊销的令牌ID和时间戳
    QMutex revocationMutex; // 保护吊销令牌集合的线程安全
    void loadSecretKey();
}