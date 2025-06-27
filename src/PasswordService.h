#ifndef PASSWORDSERVICE_H
#define PASSWORDSERVICE_H

#include <QString>

class PasswordService
{
public:
    // Argon2id参数配置
    static const int MEMORY_COST = 65536; // 64MB
    static const int TIME_COST = 3;       // 3次迭代
    static const int PARALLELISM = 1;     // 并行度
    static const int HASH_LENGTH = 32;    // 哈希结果长度
    static const int SALT_LENGTH = 16;    // 盐值长度

    // 生成密码哈希
    static QString generateHash(const QString &password);

    // 验证密码哈希
    static bool verifyPassword(const QString &password, const QString &hash);

private:
    // 生成随机盐值
    static QByteArray generateSalt();
};

#endif // PASSWORDSERVICE_H