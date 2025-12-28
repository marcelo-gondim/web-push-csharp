using System.Collections.Generic;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebPush.Util;

namespace WebPush.Test
{
    [TestClass]
    public class JWSSignerTest
    {
        private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        [TestMethod]
        public void TestGenerateSignature()
        {
            var decodedPrivateKey = UrlBase64.Decode(TestPrivateKey);

            var header = new Dictionary<string, object>();
            header.Add("typ", "JWT");
            header.Add("alg", "ES256");

            var jwtPayload = new Dictionary<string, object>();
            jwtPayload.Add("aud", "aud");
            jwtPayload.Add("exp", 1);
            jwtPayload.Add("sub", "subject");

            using var signer = new JwsSigner(decodedPrivateKey);
            var token = signer.GenerateSignature(header, jwtPayload);

            var tokenParts = token.Split('.');

            Assert.AreEqual(3, tokenParts.Length);

            var encodedHeader = tokenParts[0];
            var encodedPayload = tokenParts[1];
            var signature = tokenParts[2];

            var decodedHeader = Encoding.UTF8.GetString(UrlBase64.Decode(encodedHeader));
            var decodedPayload = Encoding.UTF8.GetString(UrlBase64.Decode(encodedPayload));

            Assert.AreEqual(@"{""typ"":""JWT"",""alg"":""ES256""}", decodedHeader);
            Assert.AreEqual(@"{""aud"":""aud"",""exp"":1,""sub"":""subject""}", decodedPayload);

            var decodedSignature = UrlBase64.Decode(signature);
            var decodedSignatureLength = decodedSignature.Length;

            // IEEE P1363 format always produces 64 bytes for P-256
            Assert.AreEqual(64, decodedSignatureLength);
        }
    }
}
