namespace WebPush
{
    /// <summary>
    /// Urgency level for push messages as defined in RFC 8030.
    /// This helps the user agent decide how to handle the notification.
    /// </summary>
    public enum PushUrgency
    {
        /// <summary>
        /// Device state: On power and Wi-Fi.
        /// Example: Advertisement.
        /// </summary>
        VeryLow,

        /// <summary>
        /// Device state: On either power or Wi-Fi.
        /// Example: Topic update.
        /// </summary>
        Low,

        /// <summary>
        /// Device state: On neither power nor Wi-Fi.
        /// Example: Chat or calendar message.
        /// This is the default urgency.
        /// </summary>
        Normal,

        /// <summary>
        /// Device state: Low battery.
        /// Example: Incoming phone call or time-sensitive alert.
        /// </summary>
        High
    }
}
