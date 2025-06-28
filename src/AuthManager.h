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
    QByteArray secretKey;
    QString algorithm = "HS256";  // HMAC-SHA256
    void loadSecretKey();
}