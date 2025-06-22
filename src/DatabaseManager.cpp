#include "DatabaseManager.h"
#include <QDebug>
#include <QDateTime>
#include <QCryptographicHash>
#include <QUuid>
#include <QCryptographicHash>

DatabaseManager::DatabaseManager(QObject *parent) : QObject(parent) {
    connectToDatabase();
}

DatabaseManager::~DatabaseManager() {
    if (m_db.isOpen()) {
        m_db.close();
    }
}

bool DatabaseManager::connectToDatabase(const QString &dbPath) {
    if (m_db.isOpen()) {
        m_db.close();
    }

    m_db = QSqlDatabase::addDatabase("QSQLITE");
    m_db.setDatabaseName(dbPath);

    if (!m_db.open()) {
        emit errorOccurred(QString("无法打开数据库: %1").arg(m_db.lastError().text()));
        return false;
    }

    return initializeTables();
}

bool DatabaseManager::initializeTables() {
    QSqlQuery query;

    // 创建消息表
    if (!query.exec("CREATE TABLE IF NOT EXISTS messages ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "sender TEXT NOT NULL,"
                   "receiver TEXT NOT NULL,"
                   "content TEXT NOT NULL,"
                   "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")) {
        emit errorOccurred(QString("消息表初始化失败: %1").arg(query.lastError().text()));
        return false;
    }

    // 创建用户表
    if (!query.exec("CREATE TABLE IF NOT EXISTS users ("
                   "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                   "username TEXT UNIQUE NOT NULL,"
                   "password_hash TEXT NOT NULL,"
                   "salt TEXT NOT NULL)")) {
        emit errorOccurred(QString("用户表初始化失败: %1").arg(query.lastError().text()));
        return false;
    }

    return true;
}

void DatabaseManager::sendMessage(const QString &sender, const QString &receiver, const QString &message) {
    if (!m_db.isOpen() || sender.isEmpty() || receiver.isEmpty() || message.isEmpty()) return;

    QSqlQuery query;
    query.prepare("INSERT INTO messages (sender, receiver, content) VALUES (:sender, :receiver, :content)");
    query.bindValue(":sender", sender);
    query.bindValue(":receiver", receiver);
    query.bindValue(":content", message);

    if (!query.exec()) {
        emit errorOccurred(QString("发送消息失败: %1").arg(query.lastError().text()));
    } else {
        emit messageAdded(message);
    }
}

QString DatabaseManager::getChatHistory() const {
    if (!m_db.isOpen()) return QString();

    QString history;
    QSqlQuery query("SELECT content, timestamp FROM messages ORDER BY timestamp DESC LIMIT 100");

    while (query.next()) {
        QString content = query.value(0).toString();
        QString timestamp = query.value(1).toDateTime().toString("HH:mm:ss");
        history.prepend(QString("[%1] %2\n").arg(timestamp).arg(content));
    }

    return history;
}

bool DatabaseManager::registerUser(const QString &username, const QString &password) {
    if (!m_db.isOpen()) return false;

    // 检查用户是否已存在
    QSqlQuery checkQuery;
    checkQuery.prepare("SELECT id FROM users WHERE username = :username");
    checkQuery.bindValue(":username", username);
    if (checkQuery.exec() && checkQuery.next()) {
        emit errorOccurred("用户名已存在");
        return false;
    }

    // 生成随机盐值
    QString salt = QUuid::createUuid().toString();
    QString passwordHash = hashPassword(password + salt);

    // 插入新用户
    QSqlQuery insertQuery;
    insertQuery.prepare("INSERT INTO users (username, password_hash, salt) VALUES (:username, :hash, :salt)");
    insertQuery.bindValue(":username", username);
    insertQuery.bindValue(":hash", passwordHash);
    insertQuery.bindValue(":salt", salt);

    if (!insertQuery.exec()) {
        emit errorOccurred(QString("注册失败: %1").arg(insertQuery.lastError().text()));
        return false;
    }
    return true;
}

bool DatabaseManager::authenticateUser(const QString &username, const QString &password) {
    if (!m_db.isOpen()) return false;

    QSqlQuery query;
    query.prepare("SELECT password_hash, salt FROM users WHERE username = :username");
    query.bindValue(":username", username);

    if (!query.exec() || !query.next()) {
        emit errorOccurred("用户不存在");
        return false;
    }

    QString storedHash = query.value(0).toString();
    QString salt = query.value(1).toString();
    QString inputHash = hashPassword(password + salt);

    return storedHash == inputHash;
}

QString DatabaseManager::hashPassword(const QString &password) {
    QByteArray hash = password.toUtf8();
    // 使用1000次迭代增强安全性
    for(int i = 0; i < 1000; i++) {
        hash = QCryptographicHash::hash(hash, QCryptographicHash::Sha256);
    }
    return QString(hash.toHex());
}