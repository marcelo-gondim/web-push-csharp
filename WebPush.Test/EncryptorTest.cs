using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test
{
    [TestClass]
    public class EncryptorTest
    {
        private const string TestPublicKey =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TestAuth = @"BTBZMqHH6r4Tts7J_aSIgg";

        [TestMethod]
        public void TestEncryptAesGcm()
        {
            var result = Encryptor.Encrypt(TestPublicKey, TestAuth, "test payload", ContentEncoding.AesGcm);

            Assert.IsNotNull(result.Payload);
            Assert.IsNotNull(result.Salt);
            Assert.IsNotNull(result.PublicKey);
            Assert.AreEqual(16, result.Salt.Length);
            Assert.AreEqual(65, result.PublicKey.Length);
        }

        [TestMethod]
        public void TestEncryptAes128Gcm()
        {
            var result = Encryptor.Encrypt(TestPublicKey, TestAuth, "test payload", ContentEncoding.Aes128Gcm);

            Assert.IsNotNull(result.Payload);
            Assert.IsNotNull(result.Salt);
            Assert.IsNotNull(result.PublicKey);

            // aes128gcm payload should include the header (86 bytes)
            // Header: salt (16) + record size (4) + key id length (1) + key id (65) = 86
            Assert.IsTrue(result.Payload.Length >= 86);
            Assert.AreEqual(16, result.Salt.Length);
            Assert.AreEqual(65, result.PublicKey.Length);
        }

        [TestMethod]
        public void TestAes128GcmPayloadContainsHeader()
        {
            var result = Encryptor.Encrypt(TestPublicKey, TestAuth, "test payload", ContentEncoding.Aes128Gcm);

            // Verify the header structure
            // First 16 bytes should be salt
            var saltFromPayload = new byte[16];
            Buffer.BlockCopy(result.Payload, 0, saltFromPayload, 0, 16);
            CollectionAssert.AreEqual(result.Salt, saltFromPayload);

            // Bytes 16-19: record size (4 bytes, big-endian) = 4096
            var recordSize = (result.Payload[16] << 24) | (result.Payload[17] << 16) |
                            (result.Payload[18] << 8) | result.Payload[19];
            Assert.AreEqual(4096, recordSize);

            // Byte 20: key id length = 65
            Assert.AreEqual(65, result.Payload[20]);

            // Bytes 21-85: public key (65 bytes)
            var publicKeyFromPayload = new byte[65];
            Buffer.BlockCopy(result.Payload, 21, publicKeyFromPayload, 0, 65);
            CollectionAssert.AreEqual(result.PublicKey, publicKeyFromPayload);
        }

        [TestMethod]
        public void TestAesGcmPayloadDoesNotContainHeader()
        {
            var result = Encryptor.Encrypt(TestPublicKey, TestAuth, "test payload", ContentEncoding.AesGcm);

            // aesgcm payload should not start with salt - it's just encrypted content + tag
            // The payload format is: 2-byte padding length + payload + tag (16 bytes)
            // It should be much smaller than aes128gcm for same input
            var result128 = Encryptor.Encrypt(TestPublicKey, TestAuth, "test payload", ContentEncoding.Aes128Gcm);

            // aes128gcm has 86-byte header overhead, aesgcm doesn't
            Assert.IsTrue(result128.Payload.Length - result.Payload.Length >= 80);
        }

        [TestMethod]
        public void TestEncryptWithByteArrays()
        {
            var userKey = UrlBase64.Decode(TestPublicKey);
            var userSecret = UrlBase64.Decode(TestAuth);
            var payload = Encoding.UTF8.GetBytes("test payload");

            var resultAesGcm = Encryptor.Encrypt(userKey, userSecret, payload, ContentEncoding.AesGcm);
            var resultAes128Gcm = Encryptor.Encrypt(userKey, userSecret, payload, ContentEncoding.Aes128Gcm);

            Assert.IsNotNull(resultAesGcm.Payload);
            Assert.IsNotNull(resultAes128Gcm.Payload);
        }

        [TestMethod]
        public void TestDefaultEncodingIsAes128Gcm()
        {
            var userKey = UrlBase64.Decode(TestPublicKey);
            var userSecret = UrlBase64.Decode(TestAuth);
            var payload = Encoding.UTF8.GetBytes("test payload");

            // Default should be Aes128Gcm
            var resultDefault = Encryptor.Encrypt(userKey, userSecret, payload);
            var resultExplicit = Encryptor.Encrypt(userKey, userSecret, payload, ContentEncoding.Aes128Gcm);

            // Both should have 86-byte header
            Assert.IsTrue(resultDefault.Payload.Length >= 86);
            Assert.IsTrue(resultExplicit.Payload.Length >= 86);
        }
    }
}
