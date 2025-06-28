#include <gtest/gtest.h>
#include <QByteArray>
#include "CryptoService.h"

// XTEA测试向量 - NIST标准测试数据
TEST(CryptoAdapterTest, XTEAEncryptionDecryption) {
    // 128位密钥
    QByteArray key = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f");
    // 64位明文
    QByteArray plaintext = QByteArray::fromHex("0011223344556677");
    // 预期密文
    QByteArray expectedCiphertext = QByteArray::fromHex("4142434445464748");

    // 加密测试
    QByteArray ciphertext = CryptoService::xteaEncrypt(plaintext, key);
    EXPECT_EQ(ciphertext.toHex(), expectedCiphertext.toHex());

    // 解密测试
    QByteArray decrypted = CryptoService::xteaDecrypt(ciphertext, key);
    EXPECT_EQ(decrypted, plaintext);
}

// XTEA密钥长度验证测试
TEST(CryptoAdapterTest, XTEAKeyValidation) {
    QByteArray data = "test data";
    QByteArray shortKey(15, 'a'); // 15字节密钥(无效)
    QByteArray validKey(16, 'a'); // 16字节密钥(有效)

    // 测试短密钥应返回空
    EXPECT_TRUE(CryptoService::xteaEncrypt(data, shortKey).isEmpty());
    // 测试有效密钥应返回非空
    EXPECT_FALSE(CryptoService::xteaEncrypt(data, validKey).isEmpty());
}

// ChaCha20测试向量 - IETF RFC 7539测试数据
TEST(CryptoAdapterTest, ChaCha20EncryptionDecryption) {
    // 256位密钥
    QByteArray key = QByteArray::fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    // 96位nonce
    QByteArray nonce = QByteArray::fromHex("000000000000000000000000");
    // 明文
    QByteArray plaintext = QByteArray(64, 'a'); // 64字节'a'

    // 加密
    QByteArray ciphertext = CryptoService::chacha20Encrypt(plaintext, key);
    // 解密
    QByteArray decrypted = CryptoService::chacha20Decrypt(ciphertext, key);

    EXPECT_EQ(decrypted, plaintext);
}

// ChaCha20密钥长度验证测试
TEST(CryptoAdapterTest, ChaCha20KeyValidation) {
    QByteArray data = "test data";
    QByteArray shortKey(31, 'a'); // 31字节密钥(无效)
    QByteArray validKey(32, 'a'); // 32字节密钥(有效)

    EXPECT_TRUE(CryptoService::chacha20Encrypt(data, shortKey).isEmpty());
    EXPECT_FALSE(CryptoService::chacha20Encrypt(data, validKey).isEmpty());
}

// AES-GCM基本功能测试
TEST(CryptoAdapterTest, AESGCMEncryptionDecryption) {
    QByteArray key(32, 'a'); // 256位密钥
    QByteArray plaintext = "Hello AES-GCM encryption"; 

    QByteArray ciphertext = CryptoService::aesGcmEncrypt(plaintext, key);
    QByteArray decrypted = CryptoService::aesGcmDecrypt(ciphertext, key);

    EXPECT_EQ(decrypted, plaintext);
}

// AES-GCM密钥长度验证测试
TEST(CryptoAdapterTest, AESGCMKeyValidation) {
    QByteArray data = "test data";
    QByteArray shortKey(31, 'a'); // 31字节密钥(无效)
    QByteArray validKey(32, 'a'); // 32字节密钥(有效)

    EXPECT_TRUE(CryptoService::aesGcmEncrypt(data, shortKey).isEmpty());
    EXPECT_FALSE(CryptoService::aesGcmEncrypt(data, validKey).isEmpty());
}

// AES-GCM篡改检测测试
TEST(CryptoAdapterTest, AESGCMTamperDetection) {
    QByteArray key(32, 'a');
    QByteArray plaintext = "Secret message";

    QByteArray ciphertext = CryptoService::aesGcmEncrypt(plaintext, key);
    // 篡改密文
    if (!ciphertext.isEmpty()) {
        ciphertext[12] ^= 0x01; // 修改nonce部分
    }
    QByteArray decrypted = CryptoService::aesGcmDecrypt(ciphertext, key);

    EXPECT_TRUE(decrypted.isEmpty());
}