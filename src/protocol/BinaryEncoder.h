#ifndef BINARYENCODER_H
#define BINARYENCODER_H

#include <QByteArray>
#include "domain/Message.h"

class BinaryEncoder {
public:
    static QByteArray encodeMessage(const Message& msg);
    static Message decodeMessage(const QByteArray& data);

private:
    static const quint32 PROTOCOL_HEADER = 0x484C4348; // 'HLC H'
    static quint32 calculateCRC32(const QByteArray& data);
};

#endif // BINARYENCODER_H