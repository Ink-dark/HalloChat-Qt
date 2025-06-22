#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QObject>
#include <QString>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>

class DatabaseManager : public QObject {
    Q_OBJECT
public:
    explicit DatabaseManager(QObject *parent = nullptr);
    ~DatabaseManager();

    Q_INVOKABLE bool connectToDatabase(const QString &dbPath = "chat.db");
    Q_INVOKABLE void sendMessage(const QString &sender, const QString &receiver, const QString &message);
    Q_INVOKABLE QString getChatHistory() const;
    Q_INVOKABLE bool registerUser(const QString &username, const QString &password);
    bool authenticateUser(const QString &username, const QString &password);

signals:
    void messageAdded(const QString &message);
    void errorOccurred(const QString &error);

private:
    QSqlDatabase m_db;
    bool initializeTables();
    QString hashPassword(const QString &password);
};

#endif // DATABASEMANAGER_H