using Krutaka.Core;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

public sealed partial class TelegramBotService
{
    /// <summary>
    /// Processes a single Telegram update through the authentication and routing pipeline.
    /// </summary>
    /// <returns>True if processing succeeded; false if it failed and should be retried.</returns>
    private async Task<bool> ProcessUpdateAsync(Update update, CancellationToken cancellationToken)
    {
        try
        {
            // Skip updates with null message (e.g., edited messages, inline queries not in allowlist)
            if (update.Message is null && update.CallbackQuery is null)
            {
                _logger.LogDebug("Skipping update {UpdateId} with no message or callback query", update.Id);
                return true; // Successfully skipped, advance offset
            }

            // Step 1: Validate authentication
            var authResult = await _authGuard.ValidateAsync(update, cancellationToken).ConfigureAwait(false);
            if (!authResult.IsValid)
            {
                _logger.LogWarning(
                    "Update {UpdateId} denied: {Reason}",
                    update.Id,
                    authResult.DeniedReason ?? "Unknown");

                // Auth denied - this is a permanent failure, advance offset
                return true;
            }

            // Step 2: Route to command handler
            var routeResult = await _router.RouteAsync(update, authResult, cancellationToken).ConfigureAwait(false);
            if (!routeResult.Routed)
            {
                _logger.LogWarning("Update {UpdateId} could not be routed", update.Id);
                return true; // Routing failed permanently, advance offset
            }

            // Step 3: Handle command based on type
            await HandleCommandAsync(routeResult, authResult, update, cancellationToken).ConfigureAwait(false);
            return true; // Successfully processed
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error processing update {UpdateId}, will retry", update.Id);
            return false; // Transient failure, do not advance offset
        }
    }

    /// <summary>
    /// Handles a routed command by dispatching to the appropriate handler.
    /// </summary>
    private async Task HandleCommandAsync(
        CommandRouteResult routeResult,
        AuthResult authResult,
        Update update,
        CancellationToken cancellationToken)
    {
        switch (routeResult.Command)
        {
            case TelegramCommand.KillSwitch:
                await HandleKillSwitchAsync(authResult.ChatId, cancellationToken).ConfigureAwait(false);
                break;

            case TelegramCommand.Help:
                await HandleHelpCommandAsync(authResult.ChatId, cancellationToken).ConfigureAwait(false);
                break;

            case TelegramCommand.Autonomy:
                await HandleAutonomyCommandAsync(authResult, update, cancellationToken).ConfigureAwait(false);
                break;

            case TelegramCommand.Budget:
                await HandleBudgetCommandAsync(authResult, update, cancellationToken).ConfigureAwait(false);
                break;

            case TelegramCommand.Status:
            case TelegramCommand.Sessions:
            case TelegramCommand.New:
            case TelegramCommand.SwitchSession:
            case TelegramCommand.Ask:
            case TelegramCommand.Task:
                // These commands require session interaction
                await HandleSessionCommandAsync(routeResult, authResult, update, cancellationToken).ConfigureAwait(false);
                break;

            case TelegramCommand.Unknown:
                _logger.LogDebug("Unknown command for update {UpdateId}", update.Id);
                break;

            default:
                _logger.LogWarning("Unhandled command type: {Command}", routeResult.Command);
                break;
        }
    }

    /// <summary>
    /// Handles the /killswitch command by terminating all sessions and stopping the application.
    /// </summary>
    private async Task HandleKillSwitchAsync(long chatId, CancellationToken cancellationToken)
    {
        _logger.LogCritical("Kill switch activated by chat {ChatId}", chatId);

        try
        {
            // Send confirmation message
            await _botClient.SendMessage(
                chatId,
                "🔴 Kill switch activated. Terminating all sessions and shutting down...",
                cancellationToken: cancellationToken).ConfigureAwait(false);

            // Terminate all active sessions
            await _sessionManager.TerminateAllAsync(cancellationToken).ConfigureAwait(false);

            _logger.LogCritical("All sessions terminated, initiating application shutdown");

            // Trigger application shutdown
            _hostLifetime.StopApplication();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during kill switch execution");
            throw;
        }
    }

    /// <summary>
    /// Handles the /help command by sending a help message.
    /// </summary>
    private async Task HandleHelpCommandAsync(long chatId, CancellationToken cancellationToken)
    {
        const string helpText = """
            *Krutaka Bot Commands*

            • Send any message to interact with the AI agent
            • /help \- Show this help message
            • /status \- Show current session status
            • /sessions \- List all active sessions
            • /new \- Start a new session
            • /session \<id\> \- Switch to a specific session
            • /budget \- Show token budget usage
            • /autonomy \- Show current autonomy level
            • /killswitch \- Emergency shutdown \(admin only\)
            """;

        await _botClient.SendMessage(
            chatId,
            helpText,
            parseMode: ParseMode.MarkdownV2,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Handles the /autonomy command by displaying the current autonomy level for the session.
    /// </summary>
    private async Task HandleAutonomyCommandAsync(
        AuthResult authResult,
        Update update,
        CancellationToken cancellationToken)
    {
        try
        {
            var chatType = update.Message?.Chat.Type ?? ChatType.Private;
            var session = await _sessionBridge.GetOrCreateSessionAsync(
                authResult.ChatId,
                authResult.UserId,
                chatType,
                cancellationToken).ConfigureAwait(false);

            var message = FormatAutonomyMessage(session.AutonomyLevelProvider);

            await _botClient.SendMessage(
                authResult.ChatId,
                message,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling autonomy command");

            await _botClient.SendMessage(
                authResult.ChatId,
                "❌ An error occurred while retrieving the autonomy level.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Formats the autonomy level message for Telegram MarkdownV2.
    /// </summary>
    private static string FormatAutonomyMessage(IAutonomyLevelProvider? provider)
    {
        if (provider == null)
        {
            return "🔒 *Autonomy Level*\n\n_Not configured_";
        }

        var level = provider.GetLevel();
        var (levelCode, levelName, autoApproved, prompted) = level switch
        {
            AutonomyLevel.Supervised => (0, "Supervised", "None", "Safe, Moderate, Elevated"),
            AutonomyLevel.Guided => (1, "Guided", "Safe", "Moderate, Elevated"),
            AutonomyLevel.SemiAutonomous => (2, "Semi-Autonomous", "Safe, Moderate, Elevated", "None"),
            AutonomyLevel.Autonomous => (3, "Autonomous", "Safe, Moderate, Elevated", "None"),
            _ => ((int)level, "Unknown", "Unknown", "Unknown")
        };

        var autoApprovedEmoji = autoApproved == "None" ? "❌" : "✅";

        return $"""
            🔒 *Autonomy Level*

            Level: `{levelCode} — {levelName}`

            {autoApprovedEmoji} Auto\-Approved: {autoApproved}
            ⚠️ Prompted: {prompted}
            🚫 Blocked: Dangerous \(always\)

            _Level cannot change during this session_
            """;
    }

    /// <summary>
    /// Handles the /budget command by displaying the current task budget consumption.
    /// </summary>
    private async Task HandleBudgetCommandAsync(
        AuthResult authResult,
        Update update,
        CancellationToken cancellationToken)
    {
        try
        {
            var chatType = update.Message?.Chat.Type ?? ChatType.Private;
            var session = await _sessionBridge.GetOrCreateSessionAsync(
                authResult.ChatId,
                authResult.UserId,
                chatType,
                cancellationToken).ConfigureAwait(false);

            var message = FormatBudgetMessage(session.TaskBudgetTracker);

            await _botClient.SendMessage(
                authResult.ChatId,
                message,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling budget command");

            await _botClient.SendMessage(
                authResult.ChatId,
                "❌ An error occurred while retrieving the budget.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Formats the budget message for Telegram MarkdownV2.
    /// </summary>
    internal static string FormatBudgetMessage(ITaskBudgetTracker? tracker)
    {
        if (tracker == null)
        {
            return "📊 *Task Budget*\n\n_Budget tracking not enabled for this session_";
        }

        var snapshot = tracker.GetSnapshot();
        var budget = tracker.GetBudget();

        static string Emoji(double pct) => pct >= 1.0 ? "🛑" : pct >= 0.8 ? "⚠️" : "✅";
        static string PctLabel(double pct) => ((int)(pct * 100)).ToString(System.Globalization.CultureInfo.InvariantCulture) + "%";

        var tokensLine = $"Tokens:    `{snapshot.TokensConsumed.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)} / {budget.MaxClaudeTokens.ToString("N0", System.Globalization.CultureInfo.InvariantCulture)}` \\({PctLabel(snapshot.TokensPercentage)}\\) {Emoji(snapshot.TokensPercentage)}";
        var toolsLine = $"Tool Calls: `{snapshot.ToolCallsConsumed} / {budget.MaxToolCalls}` \\({PctLabel(snapshot.ToolCallsPercentage)}\\) {Emoji(snapshot.ToolCallsPercentage)}";
        var filesLine = $"Files:      `{snapshot.FilesModified} / {budget.MaxFilesModified}` \\({PctLabel(snapshot.FilesModifiedPercentage)}\\) {Emoji(snapshot.FilesModifiedPercentage)}";
        var procsLine = $"Processes:  `{snapshot.ProcessesSpawned} / {budget.MaxProcessesSpawned}` \\({PctLabel(snapshot.ProcessesSpawnedPercentage)}\\) {Emoji(snapshot.ProcessesSpawnedPercentage)}";

        return $"""
            📊 *Task Budget*

            {tokensLine}
            {toolsLine}
            {filesLine}
            {procsLine}

            _Budget cannot be extended by the agent_
            """;
    }

    /// <summary>
    /// Handles session-based commands by routing through the session bridge.
    /// </summary>
    private async Task HandleSessionCommandAsync(
        CommandRouteResult routeResult,
        AuthResult authResult,
        Update update,
        CancellationToken cancellationToken)
    {
        try
        {
            // Get or create session for this chat
            var chatType = update.Message?.Chat.Type ?? ChatType.Private;
            var session = await _sessionBridge.GetOrCreateSessionAsync(
                authResult.ChatId,
                authResult.UserId,
                chatType,
                cancellationToken).ConfigureAwait(false);

            // TODO: Execute command against session orchestrator and stream response
            // This will be implemented in Phase 3 when we wire the full pipeline
            _logger.LogInformation(
                "Session command {Command} for session {SessionId}",
                routeResult.Command,
                session.SessionId);

            // Placeholder: send acknowledgment
            await _botClient.SendMessage(
                authResult.ChatId,
                $"Received command: {routeResult.Command}. Session: {session.SessionId}",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Error handling session command {Command}", routeResult.Command);

            await _botClient.SendMessage(
                authResult.ChatId,
                "❌ An error occurred while processing your request.",
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
    }
}
