<h1 align="center">web-push-csharp</h1>

<p align="center">
  <a href="https://github.com/web-push-libs/web-push-csharp/actions/workflows/CI.yml">
    <img src="https://github.com/web-push-libs/web-push-csharp/actions/workflows/CI.yml/badge.svg" alt="CI Build" />
  </a>
  <a href="https://www.nuget.org/packages/WebPush/">
    <img src="https://buildstats.info/nuget/WebPush" alt="Nuget Package Details" />
  </a>
</p>

# Why

Web push requires that push messages triggered from a backend be done via the
[Web Push Protocol](https://tools.ietf.org/html/rfc8030)
and if you want to send data with your push message, you must also encrypt
that data according to the [Message Encryption for Web Push spec (RFC 8291)](https://tools.ietf.org/html/rfc8291).

This package makes it easy to send messages using modern encryption standards and VAPID authentication.

# Install

Installation is simple, just install via NuGet.

    Install-Package WebPush

**Requirements:** .NET 10.0+

> **Note:** This library uses native `System.Security.Cryptography` APIs and does not require any external cryptographic dependencies.

# Demo Project

There is a ASP.NET MVC Core demo project located [here](https://github.com/coryjthompson/WebPushDemo)

# Usage

The common use case for this library is an application server using VAPID keys.

```csharp
using WebPush;

var pushEndpoint = @"https://fcm.googleapis.com/fcm/send/efz_TLX_rLU:APA91bE6U0iybLYvv0F3mf6uDLB6....";
var p256dh = @"BKK18ZjtENC4jdhAAg9OfJacySQiDVcXMamy3SKKy7FwJcI5E0DKO9v4V2Pb8NnAPN4EVdmhO............";
var auth = @"fkJatBBEl...............";

var subject = @"mailto:example@example.com";
var publicKey = @"BDjASz8kkVBQJgWcD05uX3VxIs_gSHyuS023jnBoHBgUbg8zIJvTSQytR8MP4Z3-kzcGNVnM...............";
var privateKey = @"mryM-krWj_6IsIMGsd8wNFXGBxnx...............";

var subscription = new PushSubscription(pushEndpoint, p256dh, auth);
var vapidDetails = new VapidDetails(subject, publicKey, privateKey);

var webPushClient = new WebPushClient();
try
{
    await webPushClient.SendNotificationAsync(subscription, "payload", vapidDetails);
}
catch (WebPushException exception)
{
    Console.WriteLine("Http STATUS code" + exception.StatusCode);
}
```

## Using PushMessageOptions (Recommended)

For more control over your push messages, use the `PushMessageOptions` class:

```csharp
using WebPush;

var subscription = new PushSubscription(pushEndpoint, p256dh, auth);
var vapidDetails = new VapidDetails(subject, publicKey, privateKey);

var options = new PushMessageOptions
{
    VapidDetails = vapidDetails,
    TTL = 3600,                                    // Time-to-live in seconds (default: 4 weeks)
    Urgency = PushUrgency.High,                    // Message urgency level
    Topic = "my-topic",                            // Topic for message replacement (max 32 chars)
    ContentEncoding = ContentEncoding.Aes128Gcm    // RFC 8291 standard (default)
};

var webPushClient = new WebPushClient();
await webPushClient.SendNotificationAsync(subscription, "payload", options);
```

### Urgency Levels

The `Urgency` header helps the user agent decide how to handle the notification based on device state:

| Urgency | Device State | Example Use Case |
|---------|--------------|------------------|
| `VeryLow` | On power and Wi-Fi | Advertisements |
| `Low` | On either power or Wi-Fi | Topic updates |
| `Normal` | On neither power nor Wi-Fi (default) | Chat messages, calendar reminders |
| `High` | Low battery | Incoming calls, time-sensitive alerts |

### Topic

The `Topic` option allows message replacement. If a push message with a topic is sent and the user agent has a pending message with the same topic, the new message will replace the old one.

```csharp
var options = new PushMessageOptions
{
    VapidDetails = vapidDetails,
    Topic = "weather-update"  // Max 32 characters, URL-safe Base64 alphabet
};
```

### Content Encoding

This library supports two content encoding formats:

| Encoding | Description | When to Use |
|----------|-------------|-------------|
| `Aes128Gcm` | RFC 8291 standard | Default, recommended for all modern browsers |
| `AesGcm` | Legacy draft format | Only for compatibility with older implementations |

# API Reference

## SendNotificationAsync(subscription, payload, options, cancellationToken)

```csharp
var subscription = new PushSubscription(pushEndpoint, p256dh, auth);

var options = new PushMessageOptions
{
    VapidDetails = new VapidDetails(subject, publicKey, privateKey),
    TTL = 86400,
    Urgency = PushUrgency.Normal
};

var webPushClient = new WebPushClient();
try
{
    await webPushClient.SendNotificationAsync(subscription, "payload", options);
}
catch (WebPushException exception)
{
    Console.WriteLine("Http STATUS code" + exception.StatusCode);
}
```

> **Note:** `SendNotificationAsync()` doesn't require a payload. You can send a push notification without any data.

### Input

**Push Subscription**

The first argument must be a `PushSubscription` object containing the details for a push subscription.

**Payload**

The payload is optional, but if set, will be the data sent with a push message.

This must be a *string*.

> **Note:** In order to encrypt the *payload*, the *pushSubscription* **must**
have *p256dh* and *auth* values.

**PushMessageOptions**

Options is an optional argument containing:

| Property | Type | Description |
|----------|------|-------------|
| `VapidDetails` | `VapidDetails` | VAPID authentication details |
| `TTL` | `int` | Time-to-live in seconds (default: 2419200 = 4 weeks) |
| `Urgency` | `PushUrgency` | Message urgency: `VeryLow`, `Low`, `Normal`, `High` |
| `Topic` | `string` | Topic for message replacement (max 32 chars) |
| `ContentEncoding` | `ContentEncoding` | `Aes128Gcm` (default) or `AesGcm` (legacy) |
| `Headers` | `Dictionary<string, string>` | Additional custom headers |

<hr />

## GenerateVapidKeys()

```csharp
VapidDetails vapidKeys = VapidHelper.GenerateVapidKeys();

// Prints 2 URL Safe Base64 Encoded Strings
Console.WriteLine("Public {0}", vapidKeys.PublicKey);
Console.WriteLine("Private {0}", vapidKeys.PrivateKey);
```

### Input

None.

### Returns

Returns a `VapidDetails` object with **PublicKey** and **PrivateKey** values populated which are
URL Safe Base64 encoded strings.

> **Note:** You should create these keys once, store them and use them for all
> future messages you send.

<hr />

## GetVapidHeaders(audience, subject, publicKey, privateKey, expiration, contentEncoding)

```csharp
Uri uri = new Uri(subscription.Endpoint);
string audience = uri.Scheme + Uri.SchemeDelimiter + uri.Host;

// For aes128gcm (RFC 8291) - returns only Authorization header
Dictionary<string, string> vapidHeaders = VapidHelper.GetVapidHeaders(
    audience,
    @"mailto:example@example.com",
    publicKey,
    privateKey,
    -1,
    ContentEncoding.Aes128Gcm
);

// For legacy aesgcm - returns Authorization and Crypto-Key headers
Dictionary<string, string> legacyHeaders = VapidHelper.GetVapidHeaders(
    audience,
    @"mailto:example@example.com",
    publicKey,
    privateKey,
    -1,
    ContentEncoding.AesGcm
);
```

### Input

| Parameter | Description |
|-----------|-------------|
| `audience` | The origin of the push service |
| `subject` | The mailto or URL for your application |
| `publicKey` | The VAPID public key |
| `privateKey` | The VAPID private key |
| `expiration` | Token expiration (-1 for default 12 hours) |
| `contentEncoding` | `Aes128Gcm` or `AesGcm` |

### Returns

For `Aes128Gcm` (RFC 8292):
- `Authorization`: `vapid t=<token>, k=<publicKey>`

For `AesGcm` (legacy):
- `Authorization`: `WebPush <token>`
- `Crypto-Key`: `p256ecdsa=<publicKey>`

<hr />

# Browser Support

<table>
<thead>
<tr>
	<th><strong>Browser</strong></th>
    <th width="130px"><strong>Push without Payload</strong></th>
    <th width="130px"><strong>Push with Payload</strong></th>
    <th width="130px"><strong>VAPID</strong></th>
    <th><strong>Notes</strong></th>
</tr>
</thead>
<tbody>
<tr>
	<td>Chrome</td>
	<!-- Push without payloads support-->
   <td>✓ v42+</td>
   <!-- Push with payload support -->
   <td>✓ v50+</td>
   <!-- VAPID Support -->
   <td>✓ v52+</td>
   <td></td>
   </tr>

   <tr>
   <td>Firefox</td>

   <!-- Push without payloads support-->
   <td>✓ v44+</td>

   <!-- Push with payload support -->
   <td>✓ v44+</td>

   <!-- VAPID Support -->
   <td>✓ v46+</td>

   <td></td>
   </tr>

   <tr>
   <td>Edge</td>

   <!-- Push without payloads support-->
   <td>✓ v17+</td>

   <!-- Push with payload support -->
   <td>✓ v17+</td>

   <!-- VAPID Support -->
   <td>✓ v17+</td>

   <td></td>
   </tr>

   <tr>
   <td>Safari</td>

   <!-- Push without payloads support-->
   <td>✓ v16.1+</td>

   <!-- Push with payload support -->
   <td>✓ v16.1+</td>

   <!-- VAPID Support -->
   <td>✓ v16.1+</td>

   <td>macOS Ventura+ and iOS/iPadOS 16.4+</td>
   </tr>

   <tr>
   <td>Opera</td>

   <!-- Push without payloads support-->
   <td>✓ v42+</td>

   <!-- Push with payload support -->
   <td>✓ v42+</td>

   <!-- VAPID Support -->
   <td>✓ v42+</td>

   <td></td>
   </tr>

   <tr>
   <td>Samsung Internet</td>
   <!-- Push without payloads support-->
   <td>✓ v4.0+</td>
   <!-- Push with payload support -->
   <td>✓ v5.0+</td>

   <!-- VAPID Support -->
   <td>✓ v5.0+</td>

   <td></td>
   </tr>
  </tbody>
</table>

# Help

**Service Worker Cookbook**

The [Service Worker Cookbook](https://serviceworke.rs/) is full of Web Push
examples.

**Web Push Documentation**

- [RFC 8030 - Generic Event Delivery Using HTTP Push](https://tools.ietf.org/html/rfc8030)
- [RFC 8291 - Message Encryption for Web Push](https://tools.ietf.org/html/rfc8291)
- [RFC 8292 - Voluntary Application Server Identification (VAPID)](https://tools.ietf.org/html/rfc8292)

# Credits

- Ported from https://github.com/web-push-libs/web-push
- Original Encryption code from https://github.com/LogicSoftware/WebPushEncryption
