using Krutaka.Core;
using Telegram.Bot.Types;

namespace Krutaka.Telegram;

/// <summary>
/// Routes Telegram updates to appropriate command handlers with input sanitization and admin gating.
/// </summary>
public sealed class TelegramCommandRouter : ITelegramCommandRouter
{
    /// <summary>
    /// Routes a validated Telegram update to the appropriate command handler.
    /// </summary>
    /// <param name="update">The Telegram update to route.</param>
    /// <param name="authResult">The authentication result from ITelegramAuthGuard.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A <see cref="CommandRouteResult"/> containing the parsed command, arguments,
    /// sanitized input, admin-only flag, and routing success status.
    /// </returns>
    public Task<CommandRouteResult> RouteAsync(
        Update update,
        AuthResult authResult,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(authResult);

        // Extract message text (null if not a text message)
        var messageText = update.Message?.Text;

        // Parse the command
        var (command, arguments) = TelegramCommandParser.Parse(messageText);

        // Determine if this is an admin-only command
        var isAdminOnly = command is TelegramCommand.Config
                                  or TelegramCommand.Audit
                                  or TelegramCommand.KillSwitch;

        // Admin gating: reject non-admin users for admin-only commands
        if (isAdminOnly && authResult.UserRole != TelegramUserRole.Admin)
        {
            return Task.FromResult(new CommandRouteResult(
                Command: command,
                Arguments: arguments,
                SanitizedInput: null,
                IsAdminOnly: true,
                Routed: false));
        }

        // Unknown command handling
        if (command == TelegramCommand.Unknown)
        {
            return Task.FromResult(new CommandRouteResult(
                Command: command,
                Arguments: arguments,
                SanitizedInput: null,
                IsAdminOnly: false,
                Routed: false));
        }

        // Sanitize user input for commands that accept text input
        string? sanitizedInput = null;
        if (ShouldSanitizeInput(command) && !string.IsNullOrWhiteSpace(arguments))
        {
            // Extract entities from the message for sanitization
            var entities = update.Message?.Entities;

            // Command with arguments — sanitize the arguments with entity stripping
            sanitizedInput = TelegramInputSanitizer.SanitizeMessageText(
                arguments,
                authResult.UserId,
                entities);
        }

        // Successfully routed
        return Task.FromResult(new CommandRouteResult(
            Command: command,
            Arguments: arguments,
            SanitizedInput: sanitizedInput,
            IsAdminOnly: isAdminOnly,
            Routed: true));
    }

    /// <summary>
    /// Determines whether the given command requires input sanitization.
    /// </summary>
    private static bool ShouldSanitizeInput(TelegramCommand command)
    {
        return command is TelegramCommand.Ask
                       or TelegramCommand.Task
                       or TelegramCommand.SwitchSession
                       or TelegramCommand.Audit
                       or TelegramCommand.Rollback;
    }
}
