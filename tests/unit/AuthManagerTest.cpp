#include <gtest/gtest.h>
#include "../../src/AuthManager.h"
#include <QDateTime>

class AuthManagerTest : public ::testing::Test {
protected:
    AuthManager authManager;
};

TEST_F(AuthManagerTest, GenerateValidToken) {
    QString token = authManager.generateToken("user123");
    EXPECT_FALSE(token.isEmpty());
    EXPECT_TRUE(authManager.validateToken(token));
}

TEST_F(AuthManagerTest, ValidateExpiredToken) {
    // 创建一个已过期的令牌
    QJsonObject header { {"alg", "HS256"}, {"typ", "JWT"} };
    QJsonObject payload {
        {"sub", "user123"},
        {"iat", QDateTime::currentSecsSinceEpoch() - 3600},
        {"exp", QDateTime::currentSecsSinceEpoch() - 1} // 已过期
    };
    
    QByteArray headerBytes = QJsonDocument(header).toJson(QJsonDocument::Compact);
    QByteArray payloadBytes = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    QString headerBase64 = headerBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QString payloadBase64 = payloadBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    
    QByteArray signatureInput = (headerBase64 + "." + payloadBase64).toUtf8();
    QByteArray signature = QCryptographicHash::hash(signatureInput, QCryptographicHash::Sha256);
    QString signatureBase64 = signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    
    QString expiredToken = headerBase64 + "." + payloadBase64 + "." + signatureBase64;
    EXPECT_FALSE(authManager.validateToken(expiredToken));
}

TEST_F(AuthManagerTest, DetectTokenTampering) {
    QString validToken = authManager.generateToken("user123");
    QStringList parts = validToken.split(".");
    
    // 篡改载荷部分
    parts[1] = QByteArray("tampered_payload").toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QString tamperedToken = parts.join(".");
    
    EXPECT_FALSE(authManager.validateToken(tamperedToken));
}

TEST_F(AuthManagerTest, RefreshValidToken) {
    QString originalToken = authManager.generateToken("user123");
    QString newToken = authManager.refreshToken(originalToken);
    
    EXPECT_FALSE(newToken.isEmpty());
    EXPECT_NE(originalToken, newToken);
    EXPECT_TRUE(authManager.validateToken(newToken));
}

TEST_F(AuthManagerTest, GetUserIdFromValidToken) {
    QString userId = "user456";
    QString token = authManager.generateToken(userId);
    
    EXPECT_EQ(authManager.getUserIdFromToken(token), userId);
}

TEST_F(AuthManagerTest, SecureCompareFunction) {
    // 测试安全比较函数防时序攻击能力
    EXPECT_TRUE(authManager.secureCompare("valid_signature", "valid_signature"));
    EXPECT_FALSE(authManager.secureCompare("valid_signature", "invalid_signature"));
    EXPECT_FALSE(authManager.secureCompare("short", "longer")); // 长度不同
}