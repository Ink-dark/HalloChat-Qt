#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QObject>
#include <QString>
#include <QVariant>
#include <sqlite3.h>

class DatabaseManager : public QObject
{
    Q_OBJECT
public:
    explicit DatabaseManager(const QString &databasePath, QObject *parent = nullptr);
    ~DatabaseManager();

    Q_INVOKABLE bool connectToDatabase();
    Q_INVOKABLE void sendMessage(const QString &sender, const QString &receiver, const QString &message);
    Q_INVOKABLE QVariantList getChatHistory(const QString &user1, const QString &user2) const;
    Q_INVOKABLE bool registerUser(const QString &username, const QString &password);
    Q_INVOKABLE bool authenticateUser(const QString &username, const QString &password);

    // 数据库连接状态
    bool isConnected() const;

    // 执行SQL查询（无返回结果）
    bool executeQuery(const QString &sql, const QVariantList &bindValues = QVariantList());

    // 执行查询并返回结果集
    QVariantList executeSelectQuery(const QString &sql, const QVariantList &bindValues = QVariantList());

    // 事务管理
    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();

    // 获取最后一次错误信息
    QString lastError() const;

    // 获取最后插入的行ID
    qint64 lastInsertRowId() const;

signals:
    // 数据库连接状态变化
    void connectionStatusChanged(bool connected);

    // 错误发生时触发
    void errorOccurred(const QString &errorMessage);

    // 新消息添加时触发
    void messageAdded(const QString &message);

private:
    // 打开数据库连接
    bool openDatabase();

    // 关闭数据库连接
    void closeDatabase();

    // 绑定参数到SQL语句
    bool bindParameters(sqlite3_stmt *stmt, const QVariantList &bindValues);

    // SQLite数据库句柄
    sqlite3 *m_dbHandle;

    // 数据库文件路径
    QString m_databasePath;

    // 最后错误信息
    QString m_lastError;

    // 密码哈希处理
    QString hashPassword(const QString &password);
};

#endif // DATABASEMANAGER_H