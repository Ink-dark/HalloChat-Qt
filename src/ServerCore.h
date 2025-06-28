#ifndef SERVERCORE_H
#define SERVERCORE_H

#include <QWebSocketServer>
#include <QWebSocket>
#include <QThreadPool>
#include <QObject>
#include <QSslConfiguration>
#include "AuthManager.h"
#include "DatabaseManager.h"

class ServerCore : public QObject
{
    Q_OBJECT
public:
    explicit ServerCore(QObject *parent = nullptr);
    ~ServerCore();

    bool startServer(quint16 port, bool secure = false);
    void stopServer();
    void handleLogin(const QString& username, const QString& password, QWebSocket* client);
    void handleMessage(QWebSocket* client, const QByteArray& message);
    void sendError(QWebSocket* client, const QString& errorCode);
    void handleGetHistory(QWebSocket* client, const QString& userId);

    // TLS配置
    void setSslConfiguration(const QSslConfiguration &config);

signals:
    void clientConnected(QWebSocket *client);
    void clientDisconnected(QWebSocket *client);
    void messageReceived(QWebSocket *client, const QString &message);
    void serverStarted(quint16 port);
    void serverStopped();
    void errorOccurred(QString errorString);

private slots:
    void onNewConnection();
    void onClientDisconnected();
    void onBinaryMessageReceived(const QByteArray &message);
    void onTextMessageReceived(const QString &message);
    void onServerError(QWebSocketProtocol::CloseCode closeCode);

private:
    QWebSocketServer *m_webSocketServer;
    QSslConfiguration m_sslConfig;
    QList<QWebSocket *> m_clients;
    QThreadPool *m_threadPool;
    const int MAX_THREAD_COUNT = 10;
    const int MAX_CONCURRENT_CONNECTIONS = 100;
    AuthManager* authManager;
    DatabaseManager* dbManager;
};

#endif // SERVERCORE_H