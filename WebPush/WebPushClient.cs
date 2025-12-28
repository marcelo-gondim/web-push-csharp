using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using WebPush.Model;
using WebPush.Util;

[assembly: InternalsVisibleTo("WebPush.Test")]

namespace WebPush
{
    public class WebPushClient : IWebPushClient
    {
        // default TTL is 4 weeks.
        private const int DefaultTtl = 2419200;
        private readonly HttpClientHandler _httpClientHandler;

        private string _gcmApiKey;
        private HttpClient _httpClient;
        private VapidDetails _vapidDetails;

        // Used so we only cleanup internally created http clients
        private bool _isHttpClientInternallyCreated;

        public WebPushClient()
        {
        }

        public WebPushClient(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public WebPushClient(HttpClientHandler httpClientHandler)
        {
            _httpClientHandler = httpClientHandler;
        }

        protected HttpClient HttpClient
        {
            get
            {
                if (_httpClient != null)
                {
                    return _httpClient;
                }

                _isHttpClientInternallyCreated = true;
                _httpClient = _httpClientHandler == null
                    ? new HttpClient()
                    : new HttpClient(_httpClientHandler);

                return _httpClient;
            }
        }

        /// <summary>
        ///     When sending messages to a GCM endpoint you need to set the GCM API key
        ///     by either calling setGcmApiKey() or passing in the API key as an option
        ///     to sendNotification()
        /// </summary>
        /// <param name="gcmApiKey">The API key to send with the GCM request.</param>
        [Obsolete("GCM is deprecated since 2019. Use FCM with VAPID authentication instead.")]
        public void SetGcmApiKey(string gcmApiKey)
        {
            if (gcmApiKey == null)
            {
                _gcmApiKey = null;
                return;
            }

            if (string.IsNullOrEmpty(gcmApiKey))
            {
                throw new ArgumentException(@"The GCM API Key should be a non-empty string or null.");
            }

            _gcmApiKey = gcmApiKey;
        }

        /// <summary>
        ///     When marking requests where you want to define VAPID details, call this method
        ///     before sendNotifications() or pass in the details and options to
        ///     sendNotification.
        /// </summary>
        /// <param name="vapidDetails"></param>
        public void SetVapidDetails(VapidDetails vapidDetails)
        {
            VapidHelper.ValidateSubject(vapidDetails.Subject);
            VapidHelper.ValidatePublicKey(vapidDetails.PublicKey);
            VapidHelper.ValidatePrivateKey(vapidDetails.PrivateKey);

            _vapidDetails = vapidDetails;
        }

        /// <summary>
        ///     When marking requests where you want to define VAPID details, call this method
        ///     before sendNotifications() or pass in the details and options to
        ///     sendNotification.
        /// </summary>
        /// <param name="subject">This must be either a URL or a 'mailto:' address</param>
        /// <param name="publicKey">The public VAPID key as a base64 encoded string</param>
        /// <param name="privateKey">The private VAPID key as a base64 encoded string</param>
        public void SetVapidDetails(string subject, string publicKey, string privateKey)
        {
            SetVapidDetails(new VapidDetails(subject, publicKey, privateKey));
        }

        /// <summary>
        ///     Generate request details for a push notification using the new options class.
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">Options for the push message including VAPID, TTL, urgency, topic, and encoding.</param>
        /// <returns>A HttpRequestMessage object that can be sent.</returns>
        public HttpRequestMessage GenerateRequestDetails(PushSubscription subscription, string payload,
            PushMessageOptions options = null)
        {
            if (!Uri.IsWellFormedUriString(subscription.Endpoint, UriKind.Absolute))
            {
                throw new ArgumentException(@"You must pass in a subscription with at least a valid endpoint");
            }

            if (!string.IsNullOrEmpty(payload) && (string.IsNullOrEmpty(subscription.Auth) ||
                                                   string.IsNullOrEmpty(subscription.P256DH)))
            {
                throw new ArgumentException(
                    @"To send a message with a payload, the subscription must have 'auth' and 'p256dh' keys.");
            }

            options ??= new PushMessageOptions { ContentEncoding = ContentEncoding.AesGcm };

            var request = new HttpRequestMessage(HttpMethod.Post, subscription.Endpoint);
            var currentVapidDetails = options.VapidDetails ?? _vapidDetails;

#pragma warning disable CS0618 // Type or member is obsolete
            var currentGcmApiKey = options.GcmApiKey ?? _gcmApiKey;
#pragma warning restore CS0618

            // TTL header
            request.Headers.Add("TTL", options.TTL.ToString());

            // Urgency header (RFC 8030)
            if (options.Urgency != PushUrgency.Normal)
            {
                var urgencyValue = options.Urgency switch
                {
                    PushUrgency.VeryLow => "very-low",
                    PushUrgency.Low => "low",
                    PushUrgency.High => "high",
                    _ => "normal"
                };
                request.Headers.Add("Urgency", urgencyValue);
            }

            // Topic header (RFC 8030)
            if (!string.IsNullOrEmpty(options.Topic))
            {
                if (options.Topic.Length > 32)
                {
                    throw new ArgumentException("Topic must be 32 characters or less.");
                }
                request.Headers.Add("Topic", options.Topic);
            }

            // Custom headers
            if (options.Headers != null)
            {
                foreach (var header in options.Headers)
                {
                    request.Headers.Add(header.Key, header.Value);
                }
            }

            string cryptoKeyHeader = null;

            if (!string.IsNullOrEmpty(payload))
            {
                if (string.IsNullOrEmpty(subscription.P256DH) || string.IsNullOrEmpty(subscription.Auth))
                {
                    throw new ArgumentException(
                        @"Unable to send a message with payload to this subscription since it doesn't have the required encryption key");
                }

                var encryptedPayload = EncryptPayload(subscription, payload, options.ContentEncoding);

                request.Content = new ByteArrayContent(encryptedPayload.Payload);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                request.Content.Headers.ContentLength = encryptedPayload.Payload.Length;

                if (options.ContentEncoding == ContentEncoding.Aes128Gcm)
                {
                    // aes128gcm: header is included in payload, no separate headers needed
                    request.Content.Headers.ContentEncoding.Add("aes128gcm");
                }
                else
                {
                    // Legacy aesgcm: separate Encryption and Crypto-Key headers
                    request.Content.Headers.ContentEncoding.Add("aesgcm");
                    request.Headers.Add("Encryption", "salt=" + encryptedPayload.Base64EncodeSalt());
                    cryptoKeyHeader = @"dh=" + encryptedPayload.Base64EncodePublicKey();
                }
            }
            else
            {
                request.Content = new ByteArrayContent(Array.Empty<byte>());
                request.Content.Headers.ContentLength = 0;
            }

            var isGcm = subscription.Endpoint.StartsWith(@"https://android.googleapis.com/gcm/send");
            var isFcm = subscription.Endpoint.StartsWith(@"https://fcm.googleapis.com/fcm/send/");

            if (isGcm)
            {
                if (!string.IsNullOrEmpty(currentGcmApiKey))
                {
                    request.Headers.TryAddWithoutValidation("Authorization", "key=" + currentGcmApiKey);
                }
            }
            else if (currentVapidDetails != null)
            {
                var uri = new Uri(subscription.Endpoint);
                var audience = uri.Scheme + @"://" + uri.Host;

                var vapidHeaders = VapidHelper.GetVapidHeaders(audience, currentVapidDetails.Subject,
                    currentVapidDetails.PublicKey, currentVapidDetails.PrivateKey,
                    currentVapidDetails.Expiration, options.ContentEncoding);

                request.Headers.Add(@"Authorization", vapidHeaders["Authorization"]);

                if (vapidHeaders.TryGetValue("Crypto-Key", out var vapidCryptoKey))
                {
                    if (string.IsNullOrEmpty(cryptoKeyHeader))
                    {
                        cryptoKeyHeader = vapidCryptoKey;
                    }
                    else
                    {
                        cryptoKeyHeader += @";" + vapidCryptoKey;
                    }
                }
            }
            else if (isFcm && !string.IsNullOrEmpty(currentGcmApiKey))
            {
                request.Headers.TryAddWithoutValidation("Authorization", "key=" + currentGcmApiKey);
            }

            if (!string.IsNullOrEmpty(cryptoKeyHeader))
            {
                request.Headers.Add("Crypto-Key", cryptoKeyHeader);
            }

            return request;
        }

        /// <summary>
        ///     To get a request without sending a push notification call this method.
        ///     This method will throw an ArgumentException if there is an issue with the input.
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">
        ///     Options for the GCM API key and vapid keys can be passed in if they are unique for each
        ///     notification.
        /// </param>
        /// <returns>A HttpRequestMessage object that can be sent.</returns>
        [Obsolete("Use the overload with PushMessageOptions instead.")]
        public HttpRequestMessage GenerateRequestDetails(PushSubscription subscription, string payload,
            Dictionary<string, object> options)
        {
            // Convert legacy options to PushMessageOptions
            var pushOptions = new PushMessageOptions
            {
                ContentEncoding = ContentEncoding.AesGcm // Legacy behavior
            };

            if (options != null)
            {
                var validOptionsKeys = new List<string> { "headers", "gcmAPIKey", "vapidDetails", "TTL" };
                foreach (var key in options.Keys)
                {
                    if (!validOptionsKeys.Contains(key))
                    {
                        throw new ArgumentException(key + " is an invalid options. The valid options are" +
                                                    string.Join(",", validOptionsKeys));
                    }
                }

                if (options.TryGetValue("headers", out var headersObj))
                {
                    if (headersObj is Dictionary<string, object> headers)
                    {
                        pushOptions.Headers = new Dictionary<string, string>();
                        foreach (var h in headers)
                        {
                            pushOptions.Headers[h.Key] = h.Value?.ToString();
                        }
                    }
                    else
                    {
                        throw new ArgumentException("options.headers must be of type Dictionary<string,object>");
                    }
                }

                if (options.TryGetValue("gcmAPIKey", out var gcmApiKeyObj))
                {
#pragma warning disable CS0618
                    pushOptions.GcmApiKey = gcmApiKeyObj as string ??
                        throw new ArgumentException("options.gcmAPIKey must be of type string");
#pragma warning restore CS0618
                }

                if (options.TryGetValue("vapidDetails", out var vapidDetailsObj))
                {
                    pushOptions.VapidDetails = vapidDetailsObj as VapidDetails ??
                        throw new ArgumentException("options.vapidDetails must be of type VapidDetails");
                }

                if (options.TryGetValue("TTL", out var ttlObj))
                {
                    if (ttlObj is int ttl)
                    {
                        pushOptions.TTL = ttl;
                    }
                    else
                    {
                        throw new ArgumentException("options.TTL must be of type int");
                    }
                }
            }

            return GenerateRequestDetails(subscription, payload, pushOptions);
        }

        private static EncryptionResult EncryptPayload(PushSubscription subscription, string payload,
            ContentEncoding encoding)
        {
            try
            {
                return Encryptor.Encrypt(subscription.P256DH, subscription.Auth, payload, encoding);
            }
            catch (Exception ex)
            {
                if (ex is FormatException || ex is ArgumentException)
                {
                    throw new InvalidEncryptionDetailsException(
                        "Unable to encrypt the payload with the encryption key of this subscription.", subscription);
                }

                throw;
            }
        }

        /// <summary>
        ///     To send a push notification call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">Options for the push message including VAPID, TTL, urgency, topic, and encoding.</param>
        public void SendNotification(PushSubscription subscription, string payload, PushMessageOptions options)
        {
            SendNotificationAsync(subscription, payload, options).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        ///     To send a push notification call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">
        ///     Options for the GCM API key and vapid keys can be passed in if they are unique for each
        ///     notification.
        /// </param>
        [Obsolete("Use the overload with PushMessageOptions instead.")]
        public void SendNotification(PushSubscription subscription, string payload = null,
            Dictionary<string, object> options = null)
        {
#pragma warning disable CS0618
            SendNotificationAsync(subscription, payload, options).ConfigureAwait(false).GetAwaiter().GetResult();
#pragma warning restore CS0618
        }

        /// <summary>
        ///     To send a push notification call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="vapidDetails">The vapid details for the notification.</param>
        public void SendNotification(PushSubscription subscription, string payload, VapidDetails vapidDetails)
        {
            var options = new PushMessageOptions { VapidDetails = vapidDetails };
            SendNotification(subscription, payload, options);
        }

        /// <summary>
        ///     To send a push notification call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="gcmApiKey">The GCM API key</param>
        [Obsolete("GCM is deprecated since 2019. Use FCM with VAPID authentication instead.")]
        public void SendNotification(PushSubscription subscription, string payload, string gcmApiKey)
        {
#pragma warning disable CS0618
            var options = new PushMessageOptions { GcmApiKey = gcmApiKey, ContentEncoding = ContentEncoding.AesGcm };
#pragma warning restore CS0618
            SendNotification(subscription, payload, options);
        }

        /// <summary>
        ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">Options for the push message including VAPID, TTL, urgency, topic, and encoding.</param>
        /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
        public async Task SendNotificationAsync(PushSubscription subscription, string payload,
            PushMessageOptions options, CancellationToken cancellationToken = default)
        {
            var request = GenerateRequestDetails(subscription, payload, options);
            var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

            await HandleResponse(response, subscription).ConfigureAwait(false);
        }

        /// <summary>
        ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="options">
        ///     Options for the GCM API key and vapid keys can be passed in if they are unique for each
        ///     notification.
        /// </param>
        /// <param name="cancellationToken">The cancellation token to cancel operation.</param>
        [Obsolete("Use the overload with PushMessageOptions instead.")]
        public async Task SendNotificationAsync(PushSubscription subscription, string payload = null,
            Dictionary<string, object> options = null, CancellationToken cancellationToken = default)
        {
#pragma warning disable CS0618
            var request = GenerateRequestDetails(subscription, payload, options);
#pragma warning restore CS0618
            var response = await HttpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

            await HandleResponse(response, subscription).ConfigureAwait(false);
        }

        /// <summary>
        ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="vapidDetails">The vapid details for the notification.</param>
        /// <param name="cancellationToken"></param>
        public async Task SendNotificationAsync(PushSubscription subscription, string payload,
            VapidDetails vapidDetails, CancellationToken cancellationToken = default)
        {
            var options = new PushMessageOptions { VapidDetails = vapidDetails };
            await SendNotificationAsync(subscription, payload, options, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        ///     To send a push notification asynchronous call this method with a subscription, optional payload and any options
        ///     Will exception if unsuccessful
        /// </summary>
        /// <param name="subscription">The PushSubscription you wish to send the notification to.</param>
        /// <param name="payload">The payload you wish to send to the user</param>
        /// <param name="gcmApiKey">The GCM API key</param>
        /// <param name="cancellationToken"></param>
        [Obsolete("GCM is deprecated since 2019. Use FCM with VAPID authentication instead.")]
        public async Task SendNotificationAsync(PushSubscription subscription, string payload, string gcmApiKey,
            CancellationToken cancellationToken = default)
        {
#pragma warning disable CS0618
            var options = new PushMessageOptions { GcmApiKey = gcmApiKey, ContentEncoding = ContentEncoding.AesGcm };
#pragma warning restore CS0618
            await SendNotificationAsync(subscription, payload, options, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        ///     Handle Web Push responses.
        /// </summary>
        /// <param name="response"></param>
        /// <param name="subscription"></param>
        private static async Task HandleResponse(HttpResponseMessage response, PushSubscription subscription)
        {
            // Successful
            if (response.IsSuccessStatusCode)
            {
                return;
            }

            // Error
            var responseCodeMessage = @"Received unexpected response code: " + (int)response.StatusCode;
            switch (response.StatusCode)
            {
                case HttpStatusCode.BadRequest:
                    responseCodeMessage = "Bad Request";
                    break;

                case HttpStatusCode.RequestEntityTooLarge:
                    responseCodeMessage = "Payload too large";
                    break;

                case (HttpStatusCode)429:
                    responseCodeMessage = "Too many request";
                    break;

                case HttpStatusCode.NotFound:
                case HttpStatusCode.Gone:
                    responseCodeMessage = "Subscription no longer valid";
                    break;
            }

            string details = null;
            if (response.Content != null)
            {
                details = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            }

            var message = string.IsNullOrEmpty(details)
                ? responseCodeMessage
                : $"{responseCodeMessage}. Details: {details}";

            throw new WebPushException(message, subscription, response);
        }

        public void Dispose()
        {
            if (_httpClient != null && _isHttpClientInternallyCreated)
            {
                _httpClient.Dispose();
                _httpClient = null;
            }
        }
    }
}
