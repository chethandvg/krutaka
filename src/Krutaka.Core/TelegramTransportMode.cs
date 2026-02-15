namespace Krutaka.Core;

/// <summary>
/// Defines the transport mode for Telegram Bot API communication.
/// </summary>
public enum TelegramTransportMode
{
    /// <summary>
    /// Long polling mode where the bot periodically calls getUpdates.
    /// Recommended for local development and behind NAT/firewalls.
    /// </summary>
    LongPolling = 0,

    /// <summary>
    /// Webhook mode where Telegram POSTs updates to the bot's HTTPS endpoint.
    /// Recommended for production deployments with public IP addresses.
    /// </summary>
    Webhook = 1
}
