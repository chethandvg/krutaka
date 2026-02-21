namespace Krutaka.Telegram;

/// <summary>
/// Parses Telegram message text into structured commands with arguments.
/// </summary>
public static class TelegramCommandParser
{
    /// <summary>
    /// Parses message text into a TelegramCommand and optional arguments.
    /// </summary>
    /// <param name="messageText">The message text to parse.</param>
    /// <returns>
    /// A tuple containing the parsed command and any arguments.
    /// Plain text (no slash) is treated as TelegramCommand.Ask.
    /// Unrecognized commands return TelegramCommand.Unknown.
    /// </returns>
    public static (TelegramCommand Command, string? Arguments) Parse(string? messageText)
    {
        if (string.IsNullOrWhiteSpace(messageText))
        {
            return (TelegramCommand.Unknown, null);
        }

        var text = messageText.Trim();

        // Plain text without '/' prefix → treat as implicit /ask
        if (!text.StartsWith('/'))
        {
            return (TelegramCommand.Ask, text);
        }

        // Split on first whitespace to separate command from arguments
        var parts = text.Split([' ', '\t', '\n'], 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return (TelegramCommand.Unknown, null);
        }

        var commandPart = parts[0];
        var arguments = parts.Length > 1 ? parts[1].Trim() : null;

        // Strip bot mention syntax from command (e.g., /ask@krutaka_bot → /ask)
        var atIndex = commandPart.IndexOf('@', StringComparison.Ordinal);
        if (atIndex > 0)
        {
            commandPart = commandPart[..atIndex];
        }

        // Remove leading '/' and convert to uppercase for case-insensitive matching (CA1308 compliance)
        var commandName = commandPart.TrimStart('/').ToUpperInvariant();

        var command = commandName switch
        {
            "ASK" => TelegramCommand.Ask,
            "TASK" => TelegramCommand.Task,
            "STATUS" => TelegramCommand.Status,
            "ABORT" => TelegramCommand.Abort,
            "KILLSWITCH" => TelegramCommand.KillSwitch,
            "SESSIONS" => TelegramCommand.Sessions,
            "SESSION" => TelegramCommand.SwitchSession,
            "HELP" => TelegramCommand.Help,
            "CONFIG" => TelegramCommand.Config,
            "AUDIT" => TelegramCommand.Audit,
            "BUDGET" => TelegramCommand.Budget,
            "AUTONOMY" => TelegramCommand.Autonomy,
            "NEW" => TelegramCommand.New,
            "CHECKPOINT" => TelegramCommand.Checkpoint,
            "ROLLBACK" => TelegramCommand.Rollback,
            _ => TelegramCommand.Unknown
        };

        return (command, arguments);
    }
}
