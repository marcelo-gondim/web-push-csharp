using System;
using System.Collections.Generic;

namespace WebPush
{
    /// <summary>
    /// Options for sending a push notification message.
    /// </summary>
    public class PushMessageOptions
    {
        /// <summary>
        /// VAPID authentication details.
        /// </summary>
        public VapidDetails VapidDetails { get; set; }

        /// <summary>
        /// Time-to-live in seconds. Default is 4 weeks (2419200 seconds).
        /// </summary>
        public int TTL { get; set; } = 2419200;

        /// <summary>
        /// Message urgency level. Default is Normal.
        /// </summary>
        public PushUrgency Urgency { get; set; } = PushUrgency.Normal;

        /// <summary>
        /// Topic for message replacement. Maximum 32 characters from URL-safe Base64 alphabet.
        /// If a push message with a topic is sent and the user agent has a pending message
        /// with the same topic, the new message will replace the old one.
        /// </summary>
        public string Topic { get; set; }

        /// <summary>
        /// Content encoding to use. Default is Aes128Gcm (RFC 8291).
        /// Use AesGcm only for compatibility with older browsers.
        /// </summary>
        public ContentEncoding ContentEncoding { get; set; } = ContentEncoding.Aes128Gcm;

        /// <summary>
        /// Additional custom headers to include in the request.
        /// </summary>
        public Dictionary<string, string> Headers { get; set; }

        /// <summary>
        /// GCM API Key for legacy GCM endpoints.
        /// </summary>
        [Obsolete("GCM is deprecated since 2019. Use FCM with VAPID authentication instead.")]
        public string GcmApiKey { get; set; }
    }
}
