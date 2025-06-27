#include "ServerCore.h"
#include <QDebug>
#include <QSslKey>
#include <QSslCertificate>

ServerCore::ServerCore(QObject *parent) : QObject(parent)
    , m_webSocketServer(nullptr)
    , m_threadPool(new QThreadPool(this))
{
    m_threadPool->setMaxThreadCount(MAX_THREAD_COUNT);
}

ServerCore::~ServerCore()
{
    stopServer();
    delete m_webSocketServer;
}

bool ServerCore::startServer(quint16 port, bool secure)
{
    QWebSocketServer::SslMode sslMode = secure ? QWebSocketServer::SecureMode : QWebSocketServer::NonSecureMode;
    m_webSocketServer = new QWebSocketServer(
        QStringLiteral("HalloChat WebSocket Server"),
        sslMode,
        this
    );

    if (secure && !m_sslConfig.isNull()) {
        m_webSocketServer->setSslConfiguration(m_sslConfig);
    }

    if (!m_webSocketServer->listen(QHostAddress::Any, port)) {
        emit errorOccurred(tr("无法启动服务器: %1").arg(m_webSocketServer->errorString()));
        return false;
    }

    connect(m_webSocketServer, &QWebSocketServer::newConnection, this, &ServerCore::onNewConnection);
    connect(m_webSocketServer, &QWebSocketServer::closed, this, &ServerCore::serverStopped);
    connect(m_webSocketServer, &QWebSocketServer::serverError, this, &ServerCore::onServerError);

    qDebug() << "WebSocket服务器启动成功，监听端口:" << port << "协议:" << (secure ? "wss" : "ws");
    emit serverStarted(port);
    return true;
}

void ServerCore::stopServer()
{
    if (m_webSocketServer && m_webSocketServer->isListening()) {
        // 关闭所有客户端连接
        for (QWebSocket *client : m_clients) {
            client->close(QWebSocketProtocol::CloseCodeNormal, "服务器关闭");
            client->deleteLater();
        }
        m_clients.clear();

        m_webSocketServer->close();
        qDebug() << "WebSocket服务器已停止";
    }
}

void ServerCore::setSslConfiguration(const QSslConfiguration &config)
{
    m_sslConfig = config;
}

void ServerCore::onNewConnection()
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