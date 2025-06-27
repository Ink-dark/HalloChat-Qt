#ifndef MSGPROTOCOL_H
#define MSGPROTOCOL_H

#include <QObject>
#include <QJsonObject>
#include <QByteArray>

class MsgProtocol : public QObject
{
    Q_OBJECT
public:
    explicit MsgProtocol(QObject *parent = nullptr);

    // 协议版本
    static const QString PROTOCOL_VERSION; // v0.0.0.25.0701.0001

    // 旧版JSON消息转换为Qt二进制消息包
    QByteArray convertToBinary(const QJsonObject &jsonMsg);

    // Qt二进制消息包转换为旧版JSON消息
    QJsonObject convertToJson(const QByteArray &binaryData);

    // 验证消息格式
    bool validateMessage(const QJsonObject &jsonMsg);

    // 获取消息类型
    QString getMessageType(const QJsonObject &jsonMsg);

private:
    // 消息加密/压缩（预留接口）
    QByteArray encrypt(const QByteArray &data);
    QByteArray decrypt(const QByteArray &data);
};

#endif // MSGPROTOCOL_H