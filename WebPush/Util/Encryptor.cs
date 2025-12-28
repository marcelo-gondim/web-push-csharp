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
        private const int Aes128GcmRecordSize = 4096;

        public static EncryptionResult Encrypt(string userKey, string userSecret, string payload,
            ContentEncoding encoding = ContentEncoding.Aes128Gcm)
        {
            var userKeyBytes = UrlBase64.Decode(userKey);
            var userSecretBytes = UrlBase64.Decode(userSecret);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            return Encrypt(userKeyBytes, userSecretBytes, payloadBytes, encoding);
        }

        public static EncryptionResult Encrypt(byte[] userKey, byte[] userSecret, byte[] payload,
            ContentEncoding encoding = ContentEncoding.Aes128Gcm)
        {
            return encoding switch
            {
                ContentEncoding.Aes128Gcm => EncryptAes128Gcm(userKey, userSecret, payload),
                ContentEncoding.AesGcm => EncryptAesGcm(userKey, userSecret, payload),
                _ => throw new ArgumentException("Invalid content encoding", nameof(encoding))
            };
        }

        /// <summary>
        /// Encrypts payload using aes128gcm encoding per RFC 8291.
        /// The payload includes the encryption header.
        /// </summary>
        private static EncryptionResult EncryptAes128Gcm(byte[] userKey, byte[] userSecret, byte[] payload)
        {
            var salt = RandomNumberGenerator.GetBytes(16);

            var (serverPublicKey, _, serverEcdh) = ECKeyHelper.GenerateKeys();

            using (serverEcdh)
            using (var userEcdh = ECKeyHelper.GetPublicKey(userKey))
            {
                // ECDH key agreement
                var sharedSecret = serverEcdh.DeriveKeyMaterial(userEcdh.PublicKey);

                // IKM info for aes128gcm: "WebPush: info\0" + recipient public key + sender public key
                var ikmInfo = CreateAes128GcmInfo(userKey, serverPublicKey);
                var ikm = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, userSecret, ikmInfo);

                // CEK and nonce derivation for aes128gcm
                var cekInfo = Encoding.UTF8.GetBytes("Content-Encoding: aes128gcm\0");
                var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 16, salt, cekInfo);

                var nonceInfo = Encoding.UTF8.GetBytes("Content-Encoding: nonce\0");
                var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 12, salt, nonceInfo);

                // Add padding (delimiter byte 0x02 at the end for aes128gcm)
                var paddedPayload = AddAes128GcmPadding(payload);

                // Encrypt
                var ciphertext = new byte[paddedPayload.Length];
                var tag = new byte[16];

                using var aesGcm = new AesGcm(cek, 16);
                aesGcm.Encrypt(nonce, paddedPayload, ciphertext, tag);

                // Build the complete payload with header
                // Header: salt (16) + record size (4) + key id length (1) + key id (65)
                var header = BuildAes128GcmHeader(salt, serverPublicKey);
                var completePayload = header.Concat(ciphertext).Concat(tag).ToArray();

                return new EncryptionResult
                {
                    Salt = salt,
                    Payload = completePayload,
                    PublicKey = serverPublicKey
                };
            }
        }

        /// <summary>
        /// Encrypts payload using legacy aesgcm encoding.
        /// Salt and public key are returned separately for HTTP headers.
        /// </summary>
        private static EncryptionResult EncryptAesGcm(byte[] userKey, byte[] userSecret, byte[] payload)
        {
            var salt = RandomNumberGenerator.GetBytes(16);

            var (serverPublicKey, _, serverEcdh) = ECKeyHelper.GenerateKeys();

            using (serverEcdh)
            using (var userEcdh = ECKeyHelper.GetPublicKey(userKey))
            {
                // ECDH key agreement
                var sharedSecret = serverEcdh.DeriveKeyMaterial(userEcdh.PublicKey);

                // HKDF derivations for aesgcm
                var authInfo = Encoding.UTF8.GetBytes("Content-Encoding: auth\0");
                var prk = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, userSecret, authInfo);

                var cekInfo = CreateInfoChunk("aesgcm", userKey, serverPublicKey);
                var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, prk, 16, salt, cekInfo);

                var nonceInfo = CreateInfoChunk("nonce", userKey, serverPublicKey);
                var nonce = HKDF.DeriveKey(HashAlgorithmName.SHA256, prk, 12, salt, nonceInfo);

                var input = AddAesGcmPadding(payload);
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
            var tag = new byte[16];

            using var aesGcm = new AesGcm(cek, 16);
            aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);

            return ciphertext.Concat(tag).ToArray();
        }

        /// <summary>
        /// Creates the info parameter for aes128gcm IKM derivation.
        /// Format: "WebPush: info\0" + recipient public key (65 bytes) + sender public key (65 bytes)
        /// </summary>
        private static byte[] CreateAes128GcmInfo(byte[] recipientPublicKey, byte[] senderPublicKey)
        {
            var info = new List<byte>();
            info.AddRange(Encoding.UTF8.GetBytes("WebPush: info\0"));
            info.AddRange(recipientPublicKey);
            info.AddRange(senderPublicKey);
            return info.ToArray();
        }

        /// <summary>
        /// Builds the aes128gcm header.
        /// Format: salt (16) + record size (4, big-endian) + key id length (1) + key id (65)
        /// </summary>
        private static byte[] BuildAes128GcmHeader(byte[] salt, byte[] serverPublicKey)
        {
            var header = new byte[86]; // 16 + 4 + 1 + 65

            // Salt (16 bytes)
            Buffer.BlockCopy(salt, 0, header, 0, 16);

            // Record size (4 bytes, big-endian)
            var recordSize = BitConverter.GetBytes(Aes128GcmRecordSize);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(recordSize);
            }
            Buffer.BlockCopy(recordSize, 0, header, 16, 4);

            // Key ID length (1 byte)
            header[20] = 65;

            // Key ID (server public key, 65 bytes)
            Buffer.BlockCopy(serverPublicKey, 0, header, 21, 65);

            return header;
        }

        /// <summary>
        /// Adds padding for aes128gcm: payload + delimiter (0x02) + zeros
        /// </summary>
        private static byte[] AddAes128GcmPadding(byte[] data)
        {
            // For simplicity, we use minimal padding: just the delimiter byte
            var result = new byte[data.Length + 1];
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            result[data.Length] = 0x02; // Delimiter byte
            return result;
        }

        /// <summary>
        /// Adds padding for legacy aesgcm: 2-byte length prefix (big-endian) + payload
        /// </summary>
        private static byte[] AddAesGcmPadding(byte[] data)
        {
            var input = new byte[2 + data.Length];
            Buffer.BlockCopy(ConvertInt(0), 0, input, 0, 2);
            Buffer.BlockCopy(data, 0, input, 2, data.Length);
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

        /// <summary>
        /// Creates info chunk for legacy aesgcm encoding.
        /// </summary>
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
