#include "PasswordService.h"
#include <argon2.h>
#include <sodium.h>
#include <QByteArray>
#include <QStringList>

QByteArray PasswordService::generateSalt()
{
    if (sodium_init() < 0) {
        qFatal("libsodium initialization failed");
    }
    QByteArray salt(SALT_LENGTH, 0);
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

QString PasswordService::generateHash(const QString &password)
{
    QByteArray passwordData = password.toUtf8();
    QByteArray salt = generateSalt();
    QByteArray hash(HASH_LENGTH, 0);

    int result = argon2id_hash_raw(
        TIME_COST, MEMORY_COST, PARALLELISM,
        passwordData.data(), passwordData.size(),
        salt.data(), salt.size(),
        hash.data(), hash.size(),
        nullptr, 0, Argon2_id, ARGON2_VERSION_13
    );

    if (result != ARGON2_OK) {
        qWarning() << "Argon2 hash failed with error:" << argon2_error_message(result);
        return QString();
    }

    // 格式: $argon2id$v=19$m=65536,t=3,p=1$salt$hash
    return QString("$argon2id$v=19$m=%1,t=%2,p=%3$%4$%5")
        .arg(MEMORY_COST).arg(TIME_COST).arg(PARALLELISM)
        .arg(QString(salt.toBase64()))
        .arg(QString(hash.toBase64()));
}

bool PasswordService::verifyPassword(const QString &password, const QString &hash)
{
    QStringList parts = hash.split('$');
    if (parts.size() < 6 || parts[1] != "argon2id") {
        return false;
    }

    // 解析参数 m=65536,t=3,p=1
    QString params = parts[3];
    int memoryCost = params.section('=', 1, 1).section(',', 0, 0).toInt();
    int timeCost = params.section('=', 2, 2).section(',', 0, 0).toInt();
    int parallelism = params.section('=', 3, 3).toInt();

    QByteArray salt = QByteArray::fromBase64(parts[4].toUtf8());
    QByteArray storedHash = QByteArray::fromBase64(parts[5].toUtf8());
    QByteArray passwordData = password.toUtf8();
    QByteArray computedHash(HASH_LENGTH, 0);

    int result = argon2id_hash_raw(
        timeCost, memoryCost, parallelism,
        passwordData.data(), passwordData.size(),
        salt.data(), salt.size(),
        computedHash.data(), computedHash.size(),
        nullptr, 0, Argon2_id, ARGON2_VERSION_13
    );

    return (result == ARGON2_OK) && (computedHash == storedHash);
}