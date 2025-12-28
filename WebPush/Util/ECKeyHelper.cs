using System;
using System.Security.Cryptography;

namespace WebPush.Util
{
    internal static class ECKeyHelper
    {
        /// <summary>
        /// Parse raw 32-byte private key scalar and return ECDsa for signing
        /// </summary>
        public static ECDsa GetPrivateKeyForSigning(byte[] privateKey)
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = privateKey
            };
            ecdsa.ImportParameters(parameters);
            return ecdsa;
        }

        /// <summary>
        /// Parse raw 65-byte uncompressed public key (0x04 + X + Y)
        /// </summary>
        public static ECDiffieHellman GetPublicKey(byte[] publicKey)
        {
            if (publicKey.Length != 65 || publicKey[0] != 0x04)
                throw new ArgumentException("Invalid uncompressed P-256 public key");

            var ecdh = ECDiffieHellman.Create();
            var parameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = publicKey[1..33],
                    Y = publicKey[33..65]
                }
            };
            ecdh.ImportParameters(parameters);
            return ecdh;
        }

        /// <summary>
        /// Generate ECDH P-256 key pair
        /// </summary>
        /// <returns>Tuple of (publicKeyBytes, privateKeyBytes, ecdhInstance)</returns>
        public static (byte[] PublicKey, byte[] PrivateKey, ECDiffieHellman Ecdh) GenerateKeys()
        {
            var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var parameters = ecdh.ExportParameters(true);

            // Uncompressed format: 0x04 + X (32 bytes) + Y (32 bytes)
            var publicKey = new byte[65];
            publicKey[0] = 0x04;
            parameters.Q.X!.CopyTo(publicKey.AsSpan(1));
            parameters.Q.Y!.CopyTo(publicKey.AsSpan(33));

            return (publicKey, parameters.D!, ecdh);
        }
    }
}
