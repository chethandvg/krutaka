namespace Krutaka.Telegram;

/// <summary>
/// Result of routing a Telegram message to a command handler.
/// </summary>
/// <param name="Command">The parsed command.</param>
/// <param name="Arguments">Optional arguments extracted from the message.</param>
/// <param name="SanitizedInput">Sanitized user input wrapped in untrusted_content tags. Null for commands without user input.</param>
/// <param name="IsAdminOnly">Whether the command requires admin privileges.</param>
/// <param name="Routed">Whether the command was successfully routed. False for unknown commands or auth failures.</param>
public sealed record CommandRouteResult(
    TelegramCommand Command,
    string? Arguments,
    string? SanitizedInput,
    bool IsAdminOnly,
    bool Routed);
