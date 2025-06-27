#include "MsgProtocol.h"
#include <QDataStream>
#include <QJsonDocument>
#include <QDebug>

const QString MsgProtocol::PROTOCOL_VERSION = "v0.0.0.25.0701.0001";

MsgProtocol::MsgProtocol(QObject *parent) : QObject(parent)
{
}

QByteArray MsgProtocol::convertToBinary(const QJsonObject &jsonMsg)
{
    if (!validateMessage(jsonMsg)) {
        qWarning() << "Invalid message format, cannot convert to binary";
        return QByteArray();
    }

    // 二进制格式: [协议版本长度(4字节)][协议版本][JSON数据长度(4字节)][JSON数据]
    QByteArray jsonData = QJsonDocument(jsonMsg).toJson(QJsonDocument::Compact);
    QByteArray versionData = PROTOCOL_VERSION.toUtf8();

    QByteArray binaryData;
    QDataStream stream(&binaryData, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::BigEndian);

    // 写入协议版本
    stream << (quint32)versionData.size();
    stream.writeRawData(versionData.constData(), versionData.size());

    // 写入JSON数据
    stream << (quint32)jsonData.size();
    stream.writeRawData(jsonData.constData(), jsonData.size());

    return encrypt(binaryData);
}

QJsonObject MsgProtocol::convertToJson(const QByteArray &binaryData)
{
    QByteArray decryptedData = decrypt(binaryData);
    QDataStream stream(decryptedData);
    stream.setByteOrder(QDataStream::BigEndian);

    // 读取协议版本
    quint32 versionSize;
    stream >> versionSize;
    QByteArray versionData(versionSize, 0);
    stream.readRawData(versionData.data(), versionSize);

    if (QString(versionData) != PROTOCOL_VERSION) {
        qWarning() << "Protocol version mismatch. Expected:" << PROTOCOL_VERSION << "Got:" << versionData;
        return QJsonObject();
    }

    // 读取JSON数据
    quint32 jsonSize;
    stream >> jsonSize;
    QByteArray jsonData(jsonSize, 0);
    stream.readRawData(jsonData.data(), jsonSize);

    QJsonDocument doc = QJsonDocument::fromJson(jsonData);
    if (!doc.isObject()) {
        qWarning() << "Invalid JSON data in binary message";
        return QJsonObject();
    }

    QJsonObject jsonMsg = doc.object();
    if (validateMessage(jsonMsg)) {
        return jsonMsg;
    }

    return QJsonObject();
}

bool MsgProtocol::validateMessage(const QJsonObject &jsonMsg)
{
    // 验证消息必须包含的字段
    if (!jsonMsg.contains("type") || !jsonMsg["type"].isString()) {
        qWarning() << "Message missing or invalid 'type' field";
        return false;
    }

    if (!jsonMsg.contains("timestamp") || !jsonMsg["timestamp"].isDouble()) {
        qWarning() << "Message missing or invalid 'timestamp' field";
        return false;
    }

    return true;
}

QString MsgProtocol::getMessageType(const QJsonObject &jsonMsg)
{
    return jsonMsg["type"].toString();
}

QByteArray MsgProtocol::encrypt(const QByteArray &data)
{
    // 预留加密实现
    return data;
}

QByteArray MsgProtocol::decrypt(const QByteArray &data)
{
    // 预留解密实现
    return data;
}