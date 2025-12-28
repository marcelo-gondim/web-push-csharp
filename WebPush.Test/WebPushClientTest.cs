using Microsoft.VisualStudio.TestTools.UnitTesting;
using RichardSzalay.MockHttp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using WebPush.Model;

namespace WebPush.Test
{
    [TestClass]
    public class WebPushClientTest
    {
        private const string TestPublicKey =
            @"BCvKwB2lbVUYMFAaBUygooKheqcEU-GDrVRnu8k33yJCZkNBNqjZj0VdxQ2QIZa4kV5kpX9aAqyBKZHURm6eG1A";

        private const string TestPrivateKey = @"on6X5KmLEFIVvPP3cNX9kE0OF6PV9TJQXVbnKU2xEHI";

        private const string TestGcmEndpoint = @"https://android.googleapis.com/gcm/send/";

        private const string TestFcmEndpoint =
            @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6";

        private const string TestFirefoxEndpoint =
            @"https://updates.push.services.mozilla.com/wpush/v2/gBABAABgOe_sGrdrsT35ljtA4O9xCX";

        public const string TestSubject = "mailto:example@example.com";

        private MockHttpMessageHandler httpMessageHandlerMock;
        private WebPushClient client;

        [TestInitialize]
        public void InitializeTest()
        {
            httpMessageHandlerMock = new MockHttpMessageHandler();
            client = new WebPushClient(httpMessageHandlerMock.ToHttpClient());
        }

        [TestMethod]
        public void TestGcmApiKeyInOptions()
        {
            var gcmAPIKey = @"teststring";
            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);

            var options = new Dictionary<string, object>();
            options[@"gcmAPIKey"] = gcmAPIKey;
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();

            Assert.AreEqual("key=" + gcmAPIKey, authorizationHeader);

            // Test previous incorrect casing of gcmAPIKey
            var options2 = new Dictionary<string, object>();
            options2[@"gcmApiKey"] = gcmAPIKey;
            Assert.Throws<ArgumentException>(
                () => client.GenerateRequestDetails(subscription, "test payload", options2));
        }

        [TestMethod]
        public void TestSetGcmApiKey()
        {
            var gcmAPIKey = @"teststring";
            client.SetGcmApiKey(gcmAPIKey);
            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();

            Assert.AreEqual(@"key=" + gcmAPIKey, authorizationHeader);
        }

        [TestMethod]
        public void TestSetGCMAPIKeyEmptyString()
        {
            Assert.Throws<ArgumentException>(
                () => client.SetGcmApiKey(""));
        }

        [TestMethod]
        public void TestSetGcmApiKeyNonGcmPushService()
        {
            // Ensure that the API key doesn't get added on a service that doesn't accept it.
            var gcmAPIKey = @"teststring";
            client.SetGcmApiKey(gcmAPIKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");

            Assert.IsFalse(message.Headers.TryGetValues(@"Authorization", out var values));
        }

        [TestMethod]
        public void TestSetGcmApiKeyNull()
        {
            client.SetGcmApiKey(@"somestring");
            client.SetGcmApiKey(null);

            var subscription = new PushSubscription(TestGcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");

            Assert.IsFalse(message.Headers.TryGetValues("Authorization", out var values));
        }

        [TestMethod]
        public void TestSetVapidDetails()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);

            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();
            var cryptoHeader = message.Headers.GetValues(@"Crypto-Key").First();

            Assert.IsTrue(authorizationHeader.StartsWith(@"WebPush "));
            Assert.IsTrue(cryptoHeader.Contains(@"p256ecdsa"));
        }

        [TestMethod]
        public void TestFcmAddsAuthorizationHeader()
        {
            client.SetGcmApiKey(@"somestring");
            var subscription = new PushSubscription(TestFcmEndpoint, TestPublicKey, TestPrivateKey);
            var message = client.GenerateRequestDetails(subscription, @"test payload");
            var authorizationHeader = message.Headers.GetValues(@"Authorization").First();

            Assert.IsTrue(authorizationHeader.StartsWith(@"key="));
        }

        [TestMethod]
        [DataRow(HttpStatusCode.Created)]
        [DataRow(HttpStatusCode.Accepted)]
        public void TestHandlingSuccessHttpCodes(HttpStatusCode status)
        {
            TestSendNotification(status);
        }

        [TestMethod]
        [DataRow(HttpStatusCode.BadRequest, "Bad Request")]
        [DataRow(HttpStatusCode.RequestEntityTooLarge, "Payload too large")]
        [DataRow((HttpStatusCode)429, "Too many request")]
        [DataRow(HttpStatusCode.NotFound, "Subscription no longer valid")]
        [DataRow(HttpStatusCode.Gone, "Subscription no longer valid")]
        [DataRow(HttpStatusCode.InternalServerError, "Received unexpected response code: 500")]
        public void TestHandlingFailureHttpCodes(HttpStatusCode status, string expectedMessage)
        {
            var actual = Assert.Throws<WebPushException>(() => TestSendNotification(status));
            Assert.AreEqual(expectedMessage, actual.Message);
        }

        [TestMethod]
        [DataRow(HttpStatusCode.BadRequest, "authorization key missing", "Bad Request. Details: authorization key missing")]
        [DataRow(HttpStatusCode.RequestEntityTooLarge, "max size is 512", "Payload too large. Details: max size is 512")]
        [DataRow((HttpStatusCode)429, "the api is limited", "Too many request. Details: the api is limited")]
        [DataRow(HttpStatusCode.NotFound, "", "Subscription no longer valid")]
        [DataRow(HttpStatusCode.Gone, "", "Subscription no longer valid")]
        [DataRow(HttpStatusCode.InternalServerError, "internal error", "Received unexpected response code: 500. Details: internal error")]
        public void TestHandlingFailureMessages(HttpStatusCode status, string response, string expectedMessage)
        {
            var actual = Assert.Throws<WebPushException>(() => TestSendNotification(status, response));
            Assert.AreEqual(expectedMessage, actual.Message);
        }

        [TestMethod]
        [DataRow(1)]
        [DataRow(5)]
        [DataRow(10)]
        [DataRow(50)]
        public void TestHandleInvalidPublicKeys(int charactersToDrop)
        {
            var invalidKey = TestPublicKey.Substring(0, TestPublicKey.Length - charactersToDrop);

            Assert.Throws<InvalidEncryptionDetailsException>(
                () => TestSendNotification(HttpStatusCode.OK, response: null, invalidKey));
        }

        private void TestSendNotification(HttpStatusCode status, string response = null, string publicKey = TestPublicKey)
        {
            var subscription = new PushSubscription(TestFcmEndpoint, publicKey, TestPrivateKey);
            var httpContent = response == null ? null : new StringContent(response);
            httpMessageHandlerMock.When(TestFcmEndpoint).Respond(req  => new HttpResponseMessage { StatusCode = status, Content = httpContent });
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            client.SendNotification(subscription, "123");
        }

        [TestMethod]
        public void TestPushMessageOptionsBasic()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
            var options = new PushMessageOptions
            {
                TTL = 3600
            };
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);
            var ttlHeader = message.Headers.GetValues(@"TTL").First();

            Assert.AreEqual("3600", ttlHeader);
        }

        [TestMethod]
        public void TestUrgencyHeader()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            // Test High urgency
            var optionsHigh = new PushMessageOptions { Urgency = PushUrgency.High };
            var messageHigh = client.GenerateRequestDetails(subscription, @"test", optionsHigh);
            Assert.AreEqual("high", messageHigh.Headers.GetValues("Urgency").First());

            // Test Low urgency
            var optionsLow = new PushMessageOptions { Urgency = PushUrgency.Low };
            var messageLow = client.GenerateRequestDetails(subscription, @"test", optionsLow);
            Assert.AreEqual("low", messageLow.Headers.GetValues("Urgency").First());

            // Test VeryLow urgency
            var optionsVeryLow = new PushMessageOptions { Urgency = PushUrgency.VeryLow };
            var messageVeryLow = client.GenerateRequestDetails(subscription, @"test", optionsVeryLow);
            Assert.AreEqual("very-low", messageVeryLow.Headers.GetValues("Urgency").First());

            // Normal urgency should not add header (default)
            var optionsNormal = new PushMessageOptions { Urgency = PushUrgency.Normal };
            var messageNormal = client.GenerateRequestDetails(subscription, @"test", optionsNormal);
            Assert.IsFalse(messageNormal.Headers.TryGetValues("Urgency", out _));
        }

        [TestMethod]
        public void TestTopicHeader()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            var options = new PushMessageOptions { Topic = "my-topic" };
            var message = client.GenerateRequestDetails(subscription, @"test", options);
            var topicHeader = message.Headers.GetValues("Topic").First();

            Assert.AreEqual("my-topic", topicHeader);
        }

        [TestMethod]
        public void TestTopicHeaderMaxLength()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            // Topic longer than 32 characters should throw
            var options = new PushMessageOptions { Topic = "this-is-a-very-long-topic-that-exceeds-32-chars" };
            Assert.Throws<ArgumentException>(
                () => client.GenerateRequestDetails(subscription, @"test", options));
        }

        [TestMethod]
        public void TestAes128GcmEncoding()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            var options = new PushMessageOptions { ContentEncoding = ContentEncoding.Aes128Gcm };
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);

            // Check Content-Encoding header
            var contentEncoding = message.Content.Headers.ContentEncoding.First();
            Assert.AreEqual("aes128gcm", contentEncoding);

            // aes128gcm should NOT have Encryption header
            Assert.IsFalse(message.Headers.TryGetValues("Encryption", out _));

            // Authorization header should use "vapid t=..., k=..." format
            var authHeader = message.Headers.GetValues("Authorization").First();
            Assert.IsTrue(authHeader.StartsWith("vapid t="));
        }

        [TestMethod]
        public void TestAesGcmEncoding()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            var options = new PushMessageOptions { ContentEncoding = ContentEncoding.AesGcm };
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);

            // Check Content-Encoding header
            var contentEncoding = message.Content.Headers.ContentEncoding.First();
            Assert.AreEqual("aesgcm", contentEncoding);

            // aesgcm should have Encryption header
            Assert.IsTrue(message.Headers.TryGetValues("Encryption", out var encryptionValues));
            Assert.IsTrue(encryptionValues.First().StartsWith("salt="));

            // Crypto-Key header should contain both dh and p256ecdsa
            var cryptoKeyHeader = message.Headers.GetValues("Crypto-Key").First();
            Assert.IsTrue(cryptoKeyHeader.Contains("dh="));
            Assert.IsTrue(cryptoKeyHeader.Contains("p256ecdsa="));

            // Authorization header should use "WebPush ..." format
            var authHeader = message.Headers.GetValues("Authorization").First();
            Assert.IsTrue(authHeader.StartsWith("WebPush "));
        }

        [TestMethod]
        public void TestDefaultEncodingIsAes128Gcm()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            // PushMessageOptions default should be Aes128Gcm
            var options = new PushMessageOptions();
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);

            var contentEncoding = message.Content.Headers.ContentEncoding.First();
            Assert.AreEqual("aes128gcm", contentEncoding);
        }

        [TestMethod]
        public void TestVapidDetailsInOptions()
        {
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);
            var vapidDetails = new VapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var options = new PushMessageOptions { VapidDetails = vapidDetails };
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);

            Assert.IsTrue(message.Headers.TryGetValues("Authorization", out _));
        }

        [TestMethod]
        public void TestCustomHeaders()
        {
            client.SetVapidDetails(TestSubject, TestPublicKey, TestPrivateKey);
            var subscription = new PushSubscription(TestFirefoxEndpoint, TestPublicKey, TestPrivateKey);

            var options = new PushMessageOptions
            {
                Headers = new Dictionary<string, string>
                {
                    { "X-Custom-Header", "custom-value" }
                }
            };
            var message = client.GenerateRequestDetails(subscription, @"test payload", options);
            var customHeader = message.Headers.GetValues("X-Custom-Header").First();

            Assert.AreEqual("custom-value", customHeader);
        }
    }
}