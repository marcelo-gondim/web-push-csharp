using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test
{
    [TestClass]
    public class ECKeyHelperTest
    {
        private const string TestPublicKey =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        [TestMethod]
        public void TestGenerateKeys()
        {
            var (publicKey, privateKey, ecdh) = ECKeyHelper.GenerateKeys();
            ecdh.Dispose();

            Assert.AreEqual(65, publicKey.Length);
            Assert.AreEqual(32, privateKey.Length);
        }

        [TestMethod]
        public void TestGenerateKeysNoCache()
        {
            var (publicKey1, privateKey1, ecdh1) = ECKeyHelper.GenerateKeys();
            var (publicKey2, privateKey2, ecdh2) = ECKeyHelper.GenerateKeys();
            ecdh1.Dispose();
            ecdh2.Dispose();

            Assert.IsFalse(publicKey1.SequenceEqual(publicKey2));
            Assert.IsFalse(privateKey1.SequenceEqual(privateKey2));
        }

        [TestMethod]
        public void TestGetPrivateKeyForSigning()
        {
            var privateKeyBytes = UrlBase64.Decode(TestPrivateKey);
            using var ecdsa = ECKeyHelper.GetPrivateKeyForSigning(privateKeyBytes);

            // Verify we can export and the D parameter matches
            var parameters = ecdsa.ExportParameters(true);
            var importedPrivateKey = UrlBase64.Encode(parameters.D!);

            Assert.AreEqual(TestPrivateKey, importedPrivateKey);
        }

        [TestMethod]
        public void TestGetPublicKey()
        {
            var publicKeyBytes = UrlBase64.Decode(TestPublicKey);
            using var ecdh = ECKeyHelper.GetPublicKey(publicKeyBytes);

            // Verify we can export and the Q point matches
            var parameters = ecdh.ExportParameters(false);
            var exportedPublicKey = new byte[65];
            exportedPublicKey[0] = 0x04;
            parameters.Q.X!.CopyTo(exportedPublicKey, 1);
            parameters.Q.Y!.CopyTo(exportedPublicKey, 33);

            var importedPublicKey = UrlBase64.Encode(exportedPublicKey);

            Assert.AreEqual(TestPublicKey, importedPublicKey);
        }
    }
}
