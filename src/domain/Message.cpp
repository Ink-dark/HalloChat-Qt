#include "Message.h"

Message::Message(const QString& messageId, const QString& senderId, const QString& receiverId,
            const QByteArray& ciphertext, const QDateTime& timestamp)
    : messageId(messageId), senderId(senderId), receiverId(receiverId), ciphertext(ciphertext), timestamp(timestamp) {}

// Getters
QString Message::getMessageId() const { return messageId; }
QString Message::getSenderId() const { return senderId; }
QString Message::getReceiverId() const { return receiverId; }
QByteArray Message::getCiphertext() const { return ciphertext; }
QDateTime Message::getTimestamp() const { return timestamp; }

// Setters
void Message::setMessageId(const QString& messageId) { this->messageId = messageId; }
void Message::setSenderId(const QString& senderId) { this->senderId = senderId; }
void Message::setReceiverId(const QString& receiverId) { this->receiverId = receiverId; }
void Message::setCiphertext(const QByteArray& ciphertext) { this->ciphertext = ciphertext; }
void Message::setTimestamp(const QDateTime& timestamp) { this->timestamp = timestamp; }

// Serialization
QJsonObject Message::toJson() const {
    QJsonObject json;
    json["messageId"] = messageId;
    json["senderId"] = senderId;
    json["receiverId"] = receiverId;
    json["ciphertext"] = QString(ciphertext.toBase64());
    json["timestamp"] = timestamp.toMSecsSinceEpoch();
    return json;
}

Message Message::fromJson(const QJsonObject& json) {
    return Message(
        json["messageId"].toString(),
        json["senderId"].toString(),
        json["receiverId"].toString(),
        QByteArray::fromBase64(json["ciphertext"].toString().toUtf8()),
        QDateTime::fromMSecsSinceEpoch(json["timestamp"].toDouble())
    );
}

QByteArray Message::toBinary() const {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << *this;
    return data;
}

Message Message::fromBinary(const QByteArray& data) {
    Message message;
    QDataStream stream(data);
    stream >> message;
    return message;
}

QDataStream& operator<<(QDataStream& out, const Message& message) {
    out << message.messageId << message.senderId << message.receiverId;
    out << message.ciphertext;
    out << message.timestamp.toMSecsSinceEpoch();
    return out;
}

QDataStream& operator>>(QDataStream& in, Message& message) {
    quint64 msecs;
    in >> message.messageId >> message.senderId >> message.receiverId;
    in >> message.ciphertext;
    in >> msecs;
    message.timestamp = QDateTime::fromMSecsSinceEpoch(msecs);
    return in;
}