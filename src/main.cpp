#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include "DatabaseManager.h"

int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);

    QQmlApplicationEngine engine;
    DatabaseManager dbManager;

    // 暴露DatabaseManager到QML
    engine.rootContext()->setContextProperty("databaseManager", &dbManager);

    const QUrl url(u"qrc:/HalloChat/qml/App.qml"_qs);
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreated,
        &app, [url](QObject *obj, const QUrl &objUrl) {
            if (!obj && url == objUrl)
                QCoreApplication::exit(-1);
        }, Qt::QueuedConnection);
    engine.load(url);

    return app.exec();
}