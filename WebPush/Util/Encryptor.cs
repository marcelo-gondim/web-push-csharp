using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace WebPush.Util
{
    // @LogicSoftware
    // Originally from https://github.com/LogicSoftware/WebPushEncryption/blob/master/src/Encryptor.cs
    internal static class Encryptor
    {
        public static EncryptionResult Encrypt(string userKey, string userSecret, string payload)
        {
            var userKeyBytes = UrlBase64.Decode(userKey);
            var userSecretBytes = UrlBase64.Decode(userSecret);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            return Encrypt(userKeyBytes, userSecretBytes, payloadBytes);
        }

        public static EncryptionResult Encrypt(byte[] userKey, byte[] userSecret, byte[] payload)
        {
            var salt = RandomNumberGenerator.GetBytes(16);

            // Generate ephemeral server key pair
            var (serverPublicKey, _, serverEcdh) = ECKeyHelper.GenerateKeys();

            using (serverEcdh)
            using (var userEcdh = ECKeyHelper.GetPublicKey(userKey))
            {
                // ECDH key agreement
                var sharedSecret = serverEcdh.DeriveKeyMaterial(userEcdh.PublicKey);

                // HKDF derivations
                var authInfo = Encoding.UTF8.GetBytes("Content-Encoding: auth\0");
                var prk = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, userSecret, authInfo);

                var cekInfo = CreateInfoChunk("aesgcm", userKey, serverPublicKey);
                var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, prk, 16, salt, cekInfo);

                var nonceInfo = CreateInfoChunk("nonce", userKey, serverPublicKey);
                var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, prk, 12, salt, nonceInfo);

                var input = AddPaddingToInput(payload);
                var encryptedMessage = EncryptAes(nonce, cek, input);

                return new EncryptionResult
                {
                    Salt = salt,
                    Payload = encryptedMessage,
                    PublicKey = serverPublicKey
                };
            }
        }

        private static byte[] EncryptAes(byte[] nonce, byte[] cek, byte[] plaintext)
        {
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16]; // 128-bit auth tag

            using var aesGcm = new AesGcm(cek, 16);
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            // Concatenate ciphertext + tag (same format as BouncyCastle)
            return ciphertext.Concat(tag).ToArray();
        }

        private static byte[] AddPaddingToInput(byte[] data)
        {
            var input = new byte[0 + 2 + data.Length];
            Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
            Buffer.BlockCopy(data, 0, input, 0 + 2, data.Length);
            return input;
        }

        public static byte[] ConvertInt(int number)
        {
            var output = BitConverter.GetBytes(Convert.ToUInt16(number));
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(output);
            }

            return output;
        }

        public static byte[] CreateInfoChunk(string type, byte[] recipientPublicKey, byte[] senderPublicKey)
        {
            var output = new List<byte>();
            output.AddRange(Encoding.UTF8.GetBytes($"Content-Encoding: {type}\0P-256\0"));
            output.AddRange(ConvertInt(recipientPublicKey.Length));
            output.AddRange(recipientPublicKey);
            output.AddRange(ConvertInt(senderPublicKey.Length));
            output.AddRange(senderPublicKey);
            return output.ToArray();
        }
    }
}
