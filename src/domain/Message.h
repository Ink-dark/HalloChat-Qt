#ifndef MESSAGE_H
#define MESSAGE_H

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <QJsonObject>
#include <QDataStream>

class Message {
private:
    QString messageId;
    QString senderId;
    QString receiverId;
    QByteArray ciphertext;
    QDateTime timestamp;

public:
    Message() = default;
    Message(const QString& messageId, const QString& senderId, const QString& receiverId,
            const QByteArray& ciphertext, const QDateTime& timestamp);

    // Getters
    QString getMessageId() const; 
    QString getSenderId() const; 
    QString getReceiverId() const; 
    QByteArray getCiphertext() const; 
    QDateTime getTimestamp() const; 

    // Setters
    void setMessageId(const QString& messageId); 
    void setSenderId(const QString& senderId); 
    void setReceiverId(const QString& receiverId); 
    void setCiphertext(const QByteArray& ciphertext); 
    void setTimestamp(const QDateTime& timestamp); 

    // Serialization
    QJsonObject toJson() const; 
    static Message fromJson(const QJsonObject& json); 
    QByteArray toBinary() const; 
    static Message fromBinary(const QByteArray& data);
};

QDataStream& operator<<(QDataStream& out, const Message& message);
QDataStream& operator>>(QDataStream& in, Message& message);

#endif // MESSAGE_H