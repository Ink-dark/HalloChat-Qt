#include "ServerCore.h"
#include "CryptoService.h"
#include <QSslConfiguration>
#include <QSslCertificate>
#include <QSslKey>
#include <QFile>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonObject>

ServerCore::ServerCore(QObject *parent) :
    QWebSocketServer("HalloChat", QWebSocketServer::SecureMode, parent),
    m_sslConfig(QSslConfiguration::defaultConfiguration())
{
    authManager = new AuthManager(this);
    dbManager = new DatabaseManager(this);
    // 加载SSL证书和密钥
    loadSslConfiguration();

    // 连接新连接信号
    connect(this, &QWebSocketServer::newConnection, this, &ServerCore::onNewConnection);
    connect(this, &QWebSocketServer::sslErrors, this, &ServerCore::onSslErrors);
}

ServerCore::~ServerCore()
{
    stopServer();
}

bool ServerCore::startServer(quint16 port)
{
    // 设置SSL配置
    setSslConfiguration(m_sslConfig);

    if (listen(QHostAddress::Any, port)) {
        qInfo() << "WebSocket服务器已启动，监听端口:" << port;
        qInfo() << "使用TLS协议版本:" << m_sslConfig.protocol();
        return true;
    } else {
        qCritical() << "服务器启动失败:" << errorString();
        return false;
    }
}

void ServerCore::stopServer()
{
    if (isListening()) {
        // 关闭所有客户端连接
        for (auto client : m_clients) {
            client->close();
            client->deleteLater();
        }
        m_clients.clear();

        // 停止服务器监听
        close();
        qInfo() << "WebSocket服务器已关闭";
    }
}

void ServerCore::loadSslConfiguration()
{
    // 加载证书
    QFile certFile("server.crt");
    if (!certFile.open(QIODevice::ReadOnly)) {
        qCritical() << "无法打开证书文件:" << certFile.errorString();
        return;
    }
    QSslCertificate certificate(&certFile, QSsl::Pem);
    certFile.close();

    // 加载私钥
    QFile keyFile("server.key");
    if (!keyFile.open(QIODevice::ReadOnly)) {
        qCritical() << "无法打开私钥文件:" << keyFile.errorString();
        return;
    }
    QSslKey privateKey(&keyFile, QSsl::Rsa, QSsl::Pem);
    keyFile.close();

    // 配置SSL
    m_sslConfig.setProtocol(QSsl::TlsV1_3);
    m_sslConfig.setLocalCertificate(certificate);
    m_sslConfig.setPrivateKey(privateKey);
    m_sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);

    // 启用现代密码套件
    QStringList ciphers = m_sslConfig.ciphers();
    ciphers.filter("AES-GCM"); // 只保留AES-GCM密码套件
    m_sslConfig.setCiphers(ciphers);
}




void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        handleMessage(client, message.toUtf8());
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        handleMessage(client, message);
    }
}

void ServerCore::handleMessage(QWebSocket* client, const QByteArray& message)
{
    QJsonParseError parseError;
    QJsonDocument doc = QJsonDocument::fromJson(message, &parseError);
    
    if (parseError.error != QJsonParseError::NoError) {
        sendError(client, "INVALID_JSON");
        return;
    }
    
    if (!doc.isObject()) {
        sendError(client, "INVALID_FORMAT");
        return;
    }
    
    QJsonObject json = doc.object();
    QString type = json["type"].toString();
    
    // 登录请求不需要令牌验证
    if (type == "login") {
        handleLogin(json["username"].toString(), json["password"].toString(), client);
        return;
    }
    
    // 其他请求需要令牌验证
    QString token = json["token"].toString();
    if (token.isEmpty() || !authManager->validateToken(token)) {
        sendError(client, "INVALID_TOKEN");
        return;
    }
    
    // 令牌有效，提取用户ID并处理请求
    QString userId = authManager->getUserIdFromToken(token);
    if (userId.isEmpty()) {
        sendError(client, "INVALID_TOKEN");
        return;
    }
    
    // 根据请求类型路由到相应处理函数
    if (type == "get_history") {
        handleGetHistory(client, userId);
    } else if (type == "refresh_token") {
        QString newToken = authManager->refreshToken(token);
        if (!newToken.isEmpty()) {
            QJsonObject response;
            response["type"] = "token_refreshed";
            response["token"] = newToken;
            client->sendTextMessage(QJsonDocument(response).toJson(QJsonDocument::Compact));
        } else {
            sendError(client, "REFRESH_FAILED");
        }
    } else {
        // 未处理的请求类型
        sendError(client, "UNKNOWN_REQUEST");
    }
}

void ServerCore::sendError(QWebSocket* client, const QString& errorCode)
{
    QJsonObject response;
    response["type"] = "error";
    response["code"] = errorCode;
    client->sendTextMessage(QJsonDocument(response).toJson(QJsonDocument::Compact));
}

void ServerCore::handleGetHistory(QWebSocket* client, const QString& userId)
{
    // 实现消息历史查询逻辑
    QJsonObject response;
    response["type"] = "history_response";
    response["messages"] = QJsonArray(); // 实际项目中应从数据库查询
    sendMessage(client, QJsonDocument(response).toJson(QJsonDocument::Compact));
}

void ServerCore::sendMessage(QWebSocket* client, const QString& message)
{
    // 256位加密密钥（生产环境需使用安全密钥管理）
    QByteArray key = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    QByteArray encryptedData = CryptoService::encryptMessage(message, key);
    client->sendBinaryMessage(encryptedData);
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}

void ServerCore::handleLogin(const QString& username, const QString& password, QWebSocket* client)
{
    if (dbManager->validateUser(username, password)) {
        QString token = authManager->generateToken(username);
        QJsonObject response;
        response["type"] = "auth_success";
        response["token"] = token;
        client->sendTextMessage(QJsonDocument(response).toJson(QJsonDocument::Compact));
    } else {
        QJsonObject response;
        response["type"] = "auth_failure";
        response["message"] = "用户名或密码错误";
        client->sendTextMessage(QJsonDocument(response).toJson(QJsonDocument::Compact));
    }
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client)) {
        qDebug() << "客户端断开连接:" << client->peerAddress().toString();
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater();
    }
}

void ServerCore::onBinaryMessageReceived(const QByteArray &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 二进制消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, QString::fromUtf8(message));
    }
}

void ServerCore::onTextMessageReceived(const QString &message)
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client) {
        // 文本消息处理逻辑（可交给线程池处理）
        emit messageReceived(client, message);
    }
}

void ServerCore::onServerError(QWebSocketProtocol::CloseCode closeCode)
{
    emit errorOccurred(tr("服务器错误: %1").arg(m_webSocketServer->errorString()));
    qWarning() << "服务器错误代码:" << closeCode << "错误信息:" << m_webSocketServer->errorString();
}
{
    if (m_clients.size() >= MAX_CONCURRENT_CONNECTIONS) {
        QWebSocket *client = m_webSocketServer->nextPendingConnection();
        client->close(QWebSocketProtocol::CloseCodeTooManyConnections, "连接数已满");
        client->deleteLater();
        qWarning() << "拒绝新连接: 已达到最大连接数" << MAX_CONCURRENT_CONNECTIONS;
        return;
    }

    QWebSocket *client = m_webSocketServer->nextPendingConnection();
    if (!client) {
        return;
    }

    qDebug() << "新客户端连接:" << client->peerAddress().toString();

    // 连接客户端信号
    connect(client, &QWebSocket::disconnected, this, &ServerCore::onClientDisconnected);
    connect(client, &QWebSocket::binaryMessageReceived, this, &ServerCore::onBinaryMessageReceived);
    connect(client, &QWebSocket::textMessageReceived, this, &ServerCore::onTextMessageReceived);
    connect(client, QOverload<QAbstractSocket::SocketError>::of(&QWebSocket::error),
            this, [this, client](QAbstractSocket::SocketError error) {
        qWarning() << "客户端错误:" << client->errorString();
        emit errorOccurred(tr("客户端错误: %1").arg(client->errorString()));
    });

    m_clients << client;
    emit clientConnected(client);
}

void ServerCore::onClientDisconnected()
{
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());
    if (client && m_clients.contains(client