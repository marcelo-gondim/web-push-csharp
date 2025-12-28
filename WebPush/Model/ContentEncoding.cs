namespace WebPush
{
    /// <summary>
    /// Content encoding for Web Push message encryption.
    /// </summary>
    public enum ContentEncoding
    {
        /// <summary>
        /// Legacy encoding (draft-ietf-webpush-encryption).
        /// Uses separate Encryption and Crypto-Key headers.
        /// </summary>
        AesGcm,

        /// <summary>
        /// Standard encoding per RFC 8291.
        /// Includes encryption header in the payload itself.
        /// This is the recommended encoding for modern browsers.
        /// </summary>
        Aes128Gcm
    }
}
