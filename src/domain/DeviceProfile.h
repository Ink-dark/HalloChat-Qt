#ifndef DEVICEPROFILE_H
#define DEVICEPROFILE_H

#include <QJsonObject>
#include <QDataStream>

enum class EncryptionLevel {
    XTEA,
    CHACHA20,
    AES256_GCM
};

class DeviceProfile {
private:
    int maxMsgSize;
    bool supportsMedia;
    EncryptionLevel encryption;

public:
    DeviceProfile() = default;
    DeviceProfile(int maxMsgSize, bool supportsMedia, EncryptionLevel encryption);

    // Getters
    int getMaxMsgSize() const; 
    bool getSupportsMedia() const; 
    EncryptionLevel getEncryption() const; 

    // Setters
    void setMaxMsgSize(int maxMsgSize); 
    void setSupportsMedia(bool supportsMedia); 
    void setEncryption(EncryptionLevel encryption); 

    // Serialization
    QJsonObject toJson() const; 
    static DeviceProfile fromJson(const QJsonObject& json); 
    QByteArray toBinary() const; 
    static DeviceProfile fromBinary(const QByteArray& data);
};

QDataStream& operator<<(QDataStream& out, const DeviceProfile& profile);
QDataStream& operator>>(QDataStream& in, DeviceProfile& profile);
QDataStream& operator<<(QDataStream& out, const EncryptionLevel& level);
QDataStream& operator>>(QDataStream& in, EncryptionLevel& level);

#endif // DEVICEPROFILE_H