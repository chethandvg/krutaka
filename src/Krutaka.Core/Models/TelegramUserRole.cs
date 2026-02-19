namespace Krutaka.Core;

/// <summary>
/// Defines the role of a Telegram user in the bot's authorization model.
/// </summary>
public enum TelegramUserRole
{
    /// <summary>
    /// Standard user with normal permissions.
    /// Can use the bot within configured limits.
    /// </summary>
    User = 0,

    /// <summary>
    /// Administrative user with elevated permissions.
    /// Can execute emergency commands like /killswitch.
    /// </summary>
    Admin = 1
}
