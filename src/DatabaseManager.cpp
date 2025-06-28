#include "DatabaseManager.h"
#include "PasswordService.h"
#include <QDebug>
#include <QVariant>
#include <QDateTime>

DatabaseManager::DatabaseManager(const QString &databasePath, QObject *parent) :
    QObject(parent), m_dbHandle(nullptr), m_databasePath(databasePath)
{
    // 初始化数据库连接
    connectToDatabase();
}

DatabaseManager::~DatabaseManager()
{
    closeDatabase();
}

bool DatabaseManager::connectToDatabase()
{
    if (isConnected()) {
        closeDatabase();
    }

    if (openDatabase()) {
        // 初始化数据库表结构
        initializeTables();
        emit connectionStatusChanged(true);
        return true;
    }

    emit connectionStatusChanged(false);
    return false;
}

bool DatabaseManager::storeMessage(const QString& sender, const QString& receiver, const QByteArray& encryptedMsg) {
    QString sql = "INSERT INTO messages (sender, receiver, content, timestamp) VALUES (?, ?, ?, ?)";
    QVariantList bindValues;
    bindValues << sender << receiver << encryptedMsg << QDateTime::currentSecsSinceEpoch();
    return executeQuery(sql, bindValues);
}

bool DatabaseManager::openDatabase()
{
    int result = sqlite3_open(m_databasePath.toUtf8().constData(), &m_dbHandle);
    if (result != SQLITE_OK) {
        m_lastError = QString("无法打开数据库: %1").arg(sqlite3_errmsg(m_dbHandle));
        qWarning() << m_lastError;
        emit errorOccurred(m_lastError);
        sqlite3_close(m_dbHandle);
        m_dbHandle = nullptr;
        return false;
    }

    qDebug() << "成功连接到数据库:" << m_databasePath;
    return true;
}

void DatabaseManager::closeDatabase()
{
    if (m_dbHandle) {
        sqlite3_close(m_dbHandle);
        m_dbHandle = nullptr;
        qDebug() << "数据库连接已关闭";
    }
}

bool DatabaseManager::isConnected() const
{
    return m_dbHandle != nullptr;
}

bool DatabaseManager::executeQuery(const QString &sql, const QVariantList &bindValues)
{
    if (!isConnected()) {
        m_lastError = "数据库未连接";
        emit errorOccurred(m_lastError);
        return false;
    }

    sqlite3_stmt *stmt = nullptr;
    const char *tail = nullptr;
    int result = sqlite3_prepare_v2(m_dbHandle, sql.toUtf8().constData(), -1, &stmt, &tail);

    if (result != SQLITE_OK) {
        m_lastError = QString("SQL准备错误: %1 - %2").arg(sql).arg(sqlite3_errmsg(m_dbHandle));
        emit errorOccurred(m_lastError);
        return false;
    }

    // 绑定参数
    if (!bindParameters(stmt, bindValues)) {
        sqlite3_finalize(stmt);
        return false;
    }

    // 执行语句
    result = sqlite3_step(stmt);
    if (result != SQLITE_DONE) {
        m_lastError = QString("SQL执行错误: %1").arg(sqlite3_errmsg(m_dbHandle));
        emit errorOccurred(m_lastError);
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

QVariantList DatabaseManager::executeSelectQuery(const QString &sql, const QVariantList &bindValues)
{
    QVariantList resultList;

    if (!isConnected()) {
        m_lastError = "数据库未连接";
        emit errorOccurred(m_lastError);
        return resultList;
    }

    sqlite3_stmt *stmt = nullptr;
    const char *tail = nullptr;
    int result = sqlite3_prepare_v2(m_dbHandle, sql.toUtf8().constData(), -1, &stmt, &tail);

    if (result != SQLITE_OK) {
        m_lastError = QString("SQL准备错误: %1 - %2").arg(sql).arg(sqlite3_errmsg(m_dbHandle));
        emit errorOccurred(m_lastError);
        return resultList;
    }

    // 绑定参数
    if (!bindParameters(stmt, bindValues)) {
        sqlite3_finalize(stmt);
        return resultList;
    }

    // 获取结果
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        QVariantMap rowMap;
        int columnCount = sqlite3_column_count(stmt);

        for (int i = 0; i < columnCount; ++i) {
            const char *columnName = sqlite3_column_name(stmt, i);
            int columnType = sqlite3_column_type(stmt, i);
            QVariant value;

            switch (columnType) {
                case SQLITE_INTEGER:
                    value = QVariant((qlonglong)sqlite3_column_int64(stmt, i));
                    break;
                case SQLITE_TEXT:
                    value = QVariant(QString::fromUtf8((const char *)sqlite3_column_text(stmt, i)));
                    break;
                case SQLITE_BLOB:
                    value = QVariant(QByteArray((const char *)sqlite3_column_blob(stmt, i), sqlite3_column_bytes(stmt, i)));
                    break;
                case SQLITE_NULL:
                    value = QVariant(QVariant::Null);
                    break;
                default:
                    value = QVariant(QString::fromUtf8((const char *)sqlite3_column_text(stmt, i)));
            }

            rowMap[QString::fromUtf8(columnName)] = value;
        }

        resultList.append(rowMap);
    }

    if (result != SQLITE_DONE) {
        m_lastError = QString("SQL查询错误: %1").arg(sqlite3_errmsg(m_dbHandle));
        emit errorOccurred(m_lastError);
    }

    sqlite3_finalize(stmt);
    return resultList;
}

bool DatabaseManager::bindParameters(sqlite3_stmt *stmt, const QVariantList &bindValues)
{
    if (bindValues.isEmpty()) {
        return true;
    }

    for (int i = 0; i < bindValues.size(); ++i) {
        QVariant value = bindValues.at(i);
        int paramIndex = i + 1; // SQLite参数索引从1开始

        switch (value.type()) {
            case QVariant::Int:
                sqlite3_bind_int(stmt, paramIndex, value.toInt());
                break;
            case QVariant::LongLong:
                sqlite3_bind_int64(stmt, paramIndex, value.toLongLong());
                break;
            case QVariant::Double:
                sqlite3_bind_double(stmt, paramIndex, value.toDouble());
                break;
            case QVariant::String:
                sqlite3_bind_text(stmt, paramIndex, value.toString().toUtf8().constData(), -1, SQLITE_TRANSIENT);
                break;
            case QVariant::ByteArray:
                sqlite3_bind_blob(stmt, paramIndex, value.toByteArray().constData(), value.toByteArray().size(), SQLITE_TRANSIENT);
                break;
            case QVariant::Bool:
                sqlite3_bind_int(stmt, paramIndex, value.toBool() ? 1 : 0);
                break;
            case QVariant::Invalid:
                sqlite3_bind_null(stmt, paramIndex);
                break;
            default:
                m_lastError = QString("不支持的参数类型: %1").arg(value.type());
                emit errorOccurred(m_lastError);
                return false;
        }

        int bindResult = sqlite3_bind_parameter_count(stmt);
        if (bindResult != bindValues.size()) {
            m_lastError = QString("参数数量不匹配: 预期 %1, 实际 %2").arg(bindResult).arg(bindValues.size());
            emit errorOccurred(m_lastError);
            return false;
        }
    }

    return true;
}

void DatabaseManager::initializeTables()
{
    // 创建用户表
    QString userTableSql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            hash TEXT NOT NULL CHECK(length(hash) = 64),
            salt TEXT NOT NULL CHECK(length(salt) >= 16),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
    )";
    executeQuery(userTableSql);

    // 创建消息表
    QString messageTableSql = R"(
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT 0,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        );
    )";
    executeQuery(messageTableSql);

    // 创建索引
    executeQuery("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)");
    executeQuery("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)");
    executeQuery("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp)");
}

bool DatabaseManager::registerUser(const QString &username, const QString &email, const QString &password)
{
    if (!isConnected()) return false;

    // 检查用户名和邮箱是否已存在
    QVariantList userResult = executeSelectQuery(
        "SELECT id FROM users WHERE username = ? OR email = ?",
        {username, email}
    );

    if (!userResult.isEmpty()) {
        m_lastError = "用户名或邮箱已存在";
        emit errorOccurred(m_lastError);
        return false;
    }

    // 生成密码哈希
    QByteArray salt = PasswordService::generateSalt();
    QByteArray hash = PasswordService::generateHash(password, salt);

    // 插入新用户
    return executeQuery(
        "INSERT INTO users (username, email, hash, salt) VALUES (?, ?, ?, ?)",
        {username, email, QString(hash.toHex()), QString(salt.toHex())}
    );
}

bool DatabaseManager::authenticateUser(const QString &username, const QString &password)
{
    if (!isConnected()) return false;

    QVariantList userResult = executeSelectQuery(
        "SELECT id, hash, salt FROM users WHERE username = ?",
        {username}
    );

    if (userResult.isEmpty()) {
        m_lastError = "用户不存在";
        emit errorOccurred(m_lastError);
        return false;
    }

    QVariantMap user = userResult.first().toMap();
    QByteArray storedHash = QByteArray::fromHex(user["hash"].toString().toUtf8());
    QByteArray salt = QByteArray::fromHex(user["salt"].toString().toUtf8());

    if (PasswordService::verifyPassword(password, salt, storedHash)) {
        // 更新最后登录时间
        executeQuery(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            {user["id"]}
        );
        m_currentUserId = user["id"].toInt();
        emit userAuthenticated(m_currentUserId, username);
        return true;
    }

    m_lastError = "密码错误";
    emit errorOccurred(m_lastError);
    return false;
}

void DatabaseManager::sendMessage(int receiverId, const QString &content)
{
    if (!isConnected() || m_currentUserId == -1) return;

    executeQuery(
        "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
        {m_currentUserId, receiverId, content}
    );

    // 获取刚插入的消息
    QVariantList result = executeSelectQuery(
        "SELECT m.content, u.username, m.timestamp FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id = last_insert_rowid()"
    );

    if (!result.isEmpty()) {
        QVariantMap message = result.first().toMap();
        emit messageSent(
            message["username"].toString(),
            message["content"].toString(),
            message["timestamp"].toString()
        );
    }
}

QVariantList DatabaseManager::getChatHistory(int contactId, int limit, int offset)
{
    if (!isConnected() || m_currentUserId == -1) return QVariantList();

    return executeSelectQuery(
        "SELECT m.id, m.content, m.timestamp, m.sender_id = ? AS is_own, u.username "
        "FROM messages m JOIN users u ON m.sender_id = u.id "
        "WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) "
        "ORDER BY m.timestamp DESC LIMIT ? OFFSET ?",
        {m_currentUserId, m_currentUserId, contactId, contactId, m_currentUserId, limit, offset}
    );
}

QString DatabaseManager::lastError() const
{
    return m_lastError;
}

bool DatabaseManager::beginTransaction()
{
    return executeQuery("BEGIN TRANSACTION;");
}

bool DatabaseManager::commitTransaction()
{
    return executeQuery("COMMIT;");
}

bool DatabaseManager::rollbackTransaction()
{
    return executeQuery("ROLLBACK;");
}

qint64 DatabaseManager::lastInsertRowId() const
{
    if (isConnected()) {
        return sqlite3_last_insert_rowid(m_dbHandle);
    }
    return -1;
}

bool DatabaseManager::initializeTables()
{
    // 创建用户表
    QString userTableSql = "CREATE TABLE IF NOT EXISTS users ("
                          "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                          "username TEXT NOT NULL UNIQUE,"
                          "password_hash TEXT NOT NULL,"
                          "salt TEXT NOT NULL,"
                          "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                          "last_login TIMESTAMP,"
                          "CHECK(length(salt)>=16 AND length(password_hash)=64)"
                          ");";

    if (!executeQuery(userTableSql)) {
        return false;
    }

    // 创建消息表
    QString messageTableSql = "CREATE TABLE IF NOT EXISTS messages ("
                             "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                             "sender TEXT NOT NULL,"
                             "receiver TEXT NOT NULL,"
                             "content TEXT NOT NULL,"
                             "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                             "is_read INTEGER DEFAULT 0,"
                             "FOREIGN KEY(sender) REFERENCES users(username),"
                             "FOREIGN KEY(receiver) REFERENCES users(username)"
                             ");";

    if (!executeQuery(messageTableSql)) {
        return false;
    }

    // 创建索引
    executeQuery("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender);");
    executeQuery("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver);");
    executeQuery("CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);");

    return true;
}

void DatabaseManager::sendMessage(const QString &sender, const QString &receiver, const QString &message)
{
    if (!isConnected()) {
        emit errorOccurred("数据库未连接，无法发送消息");
        return;
    }

    beginTransaction();

    QString sql = "INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?);";
    QVariantList bindValues;
    bindValues << sender << receiver << message;

    if (executeQuery(sql, bindValues)) {
        commitTransaction();
        emit messageAdded(message);
        qDebug() << "消息发送成功:" << sender << "->" << receiver << ":" << message;
    } else {
        rollbackTransaction();
        emit errorOccurred("发送消息失败: " + lastError());
    }
}

QVariantList DatabaseManager::getChatHistory(const QString &user1, const QString &user2) const
{
    if (!isConnected()) {
        qWarning() << "数据库未连接，无法获取聊天历史";
        return QVariantList();
    }

    QString sql = "SELECT sender, receiver, content, timestamp FROM messages "
                  "WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) "
                  "ORDER BY timestamp ASC;";

    QVariantList bindValues;
    bindValues << user1 << user2 << user2 << user1;

    return executeSelectQuery(sql, bindValues);
}

bool DatabaseManager::registerUser(const QString &username, const QString &password)
{
    if (!isConnected()) {
        emit errorOccurred("数据库未连接，无法注册用户");
        return false;
    }

    // 检查用户是否已存在
    QString checkSql = "SELECT id FROM users WHERE username = ?;";
    QVariantList checkValues;
    checkValues << username;
    QVariantList result = executeSelectQuery(checkSql, checkValues);

    if (!result.isEmpty()) {
        emit errorOccurred("用户名已存在");
        return false;
    }

    // 生成密码哈希
    QString salt = PasswordService::generateSalt();
    QString hash = PasswordService::generateHash(password, salt);

    // 插入新用户
    beginTransaction();

    QString insertSql = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?);";
    QVariantList bindValues;
    bindValues << username << hash << salt;

    bool success = executeQuery(insertSql, bindValues);

    if (success) {
        commitTransaction();
        qDebug() << "用户注册成功:" << username;
    } else {
        rollbackTransaction();
        emit errorOccurred("注册用户失败: " + lastError());
    }

    return success;
}

bool DatabaseManager::authenticateUser(const QString &username, const QString &password)
{
    if (!isConnected()) {
        emit errorOccurred("数据库未连接，无法验证用户");
        return false;
    }

    QString sql = "SELECT password_hash, salt FROM users WHERE username = ?;";
    QVariantList bindValues;
    bindValues << username;

    QVariantList result = executeSelectQuery(sql, bindValues);
    if (result.isEmpty()) {
        emit errorOccurred("用户名不存在");
        return false;
    }

    QVariantMap userData = result.first().toMap();
    QString storedHash = userData["password_hash"].toString();
    QString salt = userData["salt"].toString();

    // 验证密码
    bool isValid = PasswordService::verifyPassword(password, salt, storedHash);

    if (isValid) {
        // 更新最后登录时间
        QString updateSql = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ?;";
        QVariantList updateValues;
        updateValues << username;
        executeQuery(updateSql, updateValues);

        qDebug() << "用户认证成功:" << username;
    } else {
        emit errorOccurred("密码错误");
    }

    return isValid;
}

QString DatabaseManager::hashPassword(const QString &password)
{
    // 此方法保留以兼容旧代码，实际使用PasswordService
    QString salt = PasswordService::generateSalt();
    return PasswordService::generateHash(password, salt);
}