using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test
{
    [TestClass]
    public class VapidHelperTest
    {
        private const string ValidAudience = @"http://example.com";
        private const string ValidSubject = @"http://example.com/example";
        private const string ValidSubjectMailto = @"mailto:example@example.com";

        private const string TestPublicKey =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        [TestMethod]
        public void TestGenerateVapidKeys()
        {
            var keys = VapidHelper.GenerateVapidKeys();
            var publicKey = UrlBase64.Decode(keys.PublicKey);
            var privateKey = UrlBase64.Decode(keys.PrivateKey);

            Assert.AreEqual(32, privateKey.Length);
            Assert.AreEqual(65, publicKey.Length);
        }

        [TestMethod]
        public void TestGenerateVapidKeysNoCache()
        {
            var keys1 = VapidHelper.GenerateVapidKeys();
            var keys2 = VapidHelper.GenerateVapidKeys();

            Assert.AreNotEqual(keys1.PublicKey, keys2.PublicKey);
            Assert.AreNotEqual(keys1.PrivateKey, keys2.PrivateKey);
        }

        [TestMethod]
        public void TestGetVapidHeaders()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;
            var headers = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey);

            Assert.IsTrue(headers.ContainsKey(@"Authorization"));
            Assert.IsTrue(headers.ContainsKey(@"Crypto-Key"));
        }

        [TestMethod]
        public void TestGetVapidHeadersAudienceNotAUrl()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;
            Assert.Throws<ArgumentException>(
                () => VapidHelper.GetVapidHeaders("invalid audience", ValidSubjectMailto, publicKey, privateKey));
        }

        [TestMethod]
        public void TestGetVapidHeadersInvalidPrivateKey()
        {
            var publicKey = UrlBase64.Encode(new byte[65]);
            var privateKey = UrlBase64.Encode(new byte[1]);

            Assert.Throws<ArgumentException>(
                () => VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey));
        }

        [TestMethod]
        public void TestGetVapidHeadersInvalidPublicKey()
        {
            var publicKey = UrlBase64.Encode(new byte[1]);
            var privateKey = UrlBase64.Encode(new byte[32]);

            Assert.Throws<ArgumentException>(
                () => VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey));
        }

        [TestMethod]
        public void TestGetVapidHeadersSubjectNotAUrlOrMailTo()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;

            Assert.Throws<ArgumentException>(
                () => VapidHelper.GetVapidHeaders(ValidAudience, @"invalid subject", publicKey, privateKey));
        }

        [TestMethod]
        public void TestGetVapidHeadersWithMailToSubject()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;
            var headers = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubjectMailto, publicKey,
                privateKey);

            Assert.IsTrue(headers.ContainsKey(@"Authorization"));
            Assert.IsTrue(headers.ContainsKey(@"Crypto-Key"));
        }

        [TestMethod]
        public void TestExpirationInPastExceptions()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;

            Assert.Throws<ArgumentException>(
                () => VapidHelper.GetVapidHeaders(ValidAudience, ValidSubjectMailto, publicKey,
                    privateKey, 1552715607));
        }

        [TestMethod]
        public void TestGetVapidHeadersAes128Gcm()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;
            var headers = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey,
                -1, ContentEncoding.Aes128Gcm);

            // aes128gcm format: only Authorization header with "vapid t=<token>, k=<key>"
            Assert.IsTrue(headers.ContainsKey(@"Authorization"));
            Assert.IsFalse(headers.ContainsKey(@"Crypto-Key"));

            var authHeader = headers[@"Authorization"];
            Assert.IsTrue(authHeader.StartsWith("vapid t="));
            Assert.IsTrue(authHeader.Contains(", k=" + publicKey));
        }

        [TestMethod]
        public void TestGetVapidHeadersAesGcm()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;
            var headers = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey,
                -1, ContentEncoding.AesGcm);

            // aesgcm format: Authorization with "WebPush <token>" + Crypto-Key header
            Assert.IsTrue(headers.ContainsKey(@"Authorization"));
            Assert.IsTrue(headers.ContainsKey(@"Crypto-Key"));

            var authHeader = headers[@"Authorization"];
            Assert.IsTrue(authHeader.StartsWith("WebPush "));

            var cryptoKey = headers[@"Crypto-Key"];
            Assert.IsTrue(cryptoKey.StartsWith("p256ecdsa="));
        }

        [TestMethod]
        public void TestDefaultEncodingIsAesGcm()
        {
            var publicKey = TestPublicKey;
            var privateKey = TestPrivateKey;

            // Default overload (no encoding parameter) uses AesGcm for backwards compatibility
            var headersDefault = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey);
            var headersAesGcm = VapidHelper.GetVapidHeaders(ValidAudience, ValidSubject, publicKey, privateKey,
                -1, ContentEncoding.AesGcm);

            // Both should have Crypto-Key header (legacy format)
            Assert.IsTrue(headersDefault.ContainsKey(@"Crypto-Key"));
            Assert.IsTrue(headersAesGcm.ContainsKey(@"Crypto-Key"));
        }
    }
}