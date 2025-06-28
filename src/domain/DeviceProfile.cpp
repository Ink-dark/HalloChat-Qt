#include "DeviceProfile.h"

DeviceProfile::DeviceProfile(int maxMsgSize, bool supportsMedia, EncryptionLevel encryption)
    : maxMsgSize(maxMsgSize), supportsMedia(supportsMedia), encryption(encryption) {}

// Getters
int DeviceProfile::getMaxMsgSize() const { return maxMsgSize; }
bool DeviceProfile::getSupportsMedia() const { return supportsMedia; }
EncryptionLevel DeviceProfile::getEncryption() const { return encryption; }

// Setters
void DeviceProfile::setMaxMsgSize(int maxMsgSize) { this->maxMsgSize = maxMsgSize; }
void DeviceProfile::setSupportsMedia(bool supportsMedia) { this->supportsMedia = supportsMedia; }
void DeviceProfile::setEncryption(EncryptionLevel encryption) { this->encryption = encryption; }

// Serialization
QJsonObject DeviceProfile::toJson() const {
    QJsonObject json;
    json["maxMsgSize"] = maxMsgSize;
    json["supportsMedia"] = supportsMedia;
    json["encryption"] = static_cast<int>(encryption);
    return json;
}

DeviceProfile DeviceProfile::fromJson(const QJsonObject& json) {
    return DeviceProfile(
        json["maxMsgSize"].toInt(),
        json["supportsMedia"].toBool(),
        static_cast<EncryptionLevel>(json["encryption"].toInt())
    );
}

QByteArray DeviceProfile::toBinary() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << *this;
    return data;
}

DeviceProfile DeviceProfile::fromBinary(const QByteArray& data) {
    DeviceProfile profile;
    QDataStream stream(data);
    stream >> profile;
    return profile;
}

QDataStream& operator<<(QDataStream& out, const DeviceProfile& profile) {
    out << profile.maxMsgSize << profile.supportsMedia;
    out << static_cast<quint8>(profile.encryption);
    return out;
}

QDataStream& operator>>(QDataStream& in, DeviceProfile& profile) {
    quint8 encryption;
    in >> profile.maxMsgSize >> profile.supportsMedia;
    in >> encryption;
    profile.encryption = static_cast<EncryptionLevel>(encryption);
    return in;
}

QDataStream& operator<<(QDataStream& out, const EncryptionLevel& level) {
    out << static_cast<quint8>(level);
    return out;
}

QDataStream& operator>>(QDataStream& in, EncryptionLevel& level) {
    quint8 val;
    in >> val;
    level = static_cast<EncryptionLevel>(val);
    return in;
}