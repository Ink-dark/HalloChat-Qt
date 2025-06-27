#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QDebug>
#include "DatabaseManager.h"
#include "ServerCore.h"
#include "MsgProtocol.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    // 初始化数据库
    DatabaseManager dbManager;
    if (!dbManager.openDatabase("chat.db")) {
        qCritical() << "无法打开数据库:" << dbManager.lastError();
        return 1;
    }

    // 初始化消息协议
    MsgProtocol msgProtocol;

    // 初始化服务器核心
    ServerCore server;
    if (!server.startServer(7932)) {
        qCritical() << "无法启动服务器:" << server.errorString();
        return 1;
    }
    qInfo() << "服务器已启动，监听端口:" << 7932;

    // 设置QML引擎
    QQmlApplicationEngine engine;
    QQmlContext *context = engine.rootContext();

    // 暴露C++对象到QML
    context->setContextProperty("databaseManager", &dbManager);
    context->setContextProperty("server", &server);
    context->setContextProperty("msgProtocol", &msgProtocol);

    const QUrl url(u"qrc:/HalloChat/qml/App.qml"_qs);
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
        &app, [url](QObject *obj, const QUrl &objUrl) {
            if (!obj && url == objUrl)
                QCoreApplication::exit(-1);
        }, Qt::QueuedConnection);
    engine.load(url);

    return app.exec();
}