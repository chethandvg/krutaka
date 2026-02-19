namespace Krutaka.Core;

/// <summary>
/// Defines the operating mode for the Krutaka host application.
/// </summary>
public enum HostMode
{
    /// <summary>
    /// Console mode — runs the local console UI with a single session.
    /// This is the default mode for backward compatibility.
    /// Telegram bot services are not registered in this mode.
    /// </summary>
    Console = 0,

    /// <summary>
    /// Telegram mode — runs as a headless Telegram bot service supporting multiple concurrent sessions.
    /// Console UI is not registered in this mode.
    /// Requires valid Telegram configuration.
    /// </summary>
    Telegram = 1,

    /// <summary>
    /// Both mode — runs both console UI and Telegram bot service concurrently.
    /// Allows interaction through both interfaces simultaneously with shared session management.
    /// Requires valid Telegram configuration.
    /// </summary>
    Both = 2
}
