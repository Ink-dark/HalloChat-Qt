#ifndef USER_H
#define USER_H

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>
#include <QDataStream>

enum class DeviceClass {
    LowPower,
    Mobile,
    Desktop
};

class User {
private:
    QString uuid;
    QString username;
    QByteArray pwdHash;
    DeviceClass deviceType;
    QDateTime createdAt;

public:
    User() = default;
    User(const QString& uuid, const QString& username, const QByteArray& pwdHash,
         DeviceClass deviceType, const QDateTime& createdAt);

    // Getters
    QString getUuid() const; 
    QString getUsername() const; 
    QByteArray getPwdHash() const; 
    DeviceClass getDeviceType() const; 
    QDateTime getCreatedAt() const; 

    // Setters
    void setUuid(const QString& uuid); 
    void setUsername(const QString& username); 
    void setPwdHash(const QByteArray& pwdHash); 
    void setDeviceType(DeviceClass deviceType); 
    void setCreatedAt(const QDateTime& createdAt); 

    // Serialization
    QJsonObject toJson() const; 
    static User fromJson(const QJsonObject& json); 
    QByteArray toBinary() const; 
    static User fromBinary(const QByteArray& data);
};

QDataStream& operator<<(QDataStream& out, const User& user);
QDataStream& operator>>(QDataStream& in, User& user);

#endif // USER_H