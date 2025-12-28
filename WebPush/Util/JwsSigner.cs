using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WebPush.Util
{
    internal class JwsSigner : IDisposable
    {
        private readonly ECDsa _ecdsa;

        public JwsSigner(byte[] privateKey)
        {
            _ecdsa = ECKeyHelper.GetPrivateKeyForSigning(privateKey);
        }

        /// <summary>
        /// Generates a JWS Signature (ES256).
        /// </summary>
        public string GenerateSignature(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var securedInput = SecureInput(header, payload);
            var message = Encoding.UTF8.GetBytes(securedInput);

            // SHA-256 hash + ECDSA sign
            var hash = SHA256.HashData(message);

            // SignHash with IEEE P1363 format returns r||s directly (64 bytes for P-256)
            var signature = _ecdsa.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            return $"{securedInput}.{UrlBase64.Encode(signature)}";
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var encodeHeader = UrlBase64.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(header)));
            var encodePayload = UrlBase64.Encode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));

            return $"{encodeHeader}.{encodePayload}";
        }

        public void Dispose()
        {
            _ecdsa?.Dispose();
        }
    }
}
