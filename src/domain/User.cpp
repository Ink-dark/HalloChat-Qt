#include "User.h"

User::User(const QString& uuid, const QString& username, const QByteArray& pwdHash,
         DeviceClass deviceType, const QDateTime& createdAt)
    : uuid(uuid), username(username), pwdHash(pwdHash), deviceType(deviceType), createdAt(createdAt) {}

// Getters
QString User::getUuid() const { return uuid; }
QString User::getUsername() const { return username; }
QByteArray User::getPwdHash() const { return pwdHash; }
DeviceClass User::getDeviceType() const { return deviceType; }
QDateTime User::getCreatedAt() const { return createdAt; }

// Setters
void User::setUuid(const QString& uuid) { this->uuid = uuid; }
void User::setUsername(const QString& username) { this->username = username; }
void User::setPwdHash(const QByteArray& pwdHash) { this->pwdHash = pwdHash; }
void User::setDeviceType(DeviceClass deviceType) { this->deviceType = deviceType; }
void User::setCreatedAt(const QDateTime& createdAt) { this->createdAt = createdAt; }

// Serialization
QJsonObject User::toJson() const {
    QJsonObject json;
    json["uuid"] = uuid;
    json["username"] = username;
    json["pwdHash"] = QString(pwdHash.toBase64());
    json["deviceType"] = static_cast<int>(deviceType);
    json["createdAt"] = createdAt.toMSecsSinceEpoch();
    return json;
}

User User::fromJson(const QJsonObject& json) {
    return User(
        json["uuid"].toString(),
        json["username"].toString(),
        QByteArray::fromBase64(json["pwdHash"].toString().toUtf8()),
        static_cast<DeviceClass>(json["deviceType"].toInt()),
        QDateTime::fromMSecsSinceEpoch(json["createdAt"].toDouble())
    );
}

QByteArray User::toBinary() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << *this;
    return data;
}

User User::fromBinary(const QByteArray& data) {
    User user;
    QDataStream stream(data);
    stream >> user;
    return user;
}

QDataStream& operator<<(QDataStream& out, const User& user) {
    out << user.uuid << user.username << user.pwdHash;
    out << static_cast<quint8>(user.deviceType);
    out << user.createdAt.toMSecsSinceEpoch();
    return out;
}

QDataStream& operator>>(QDataStream& in, User& user) {
    quint64 msecs;
    quint8 deviceType;
    in >> user.uuid >> user.username >> user.pwdHash;
    in >> deviceType;
    in >> msecs;
    user.deviceType = static_cast<DeviceClass>(deviceType);
    user.createdAt = QDateTime::fromMSecsSinceEpoch(msecs);
    return in;
}