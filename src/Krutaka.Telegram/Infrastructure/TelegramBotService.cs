using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using Krutaka.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Polling;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

/// <summary>
/// Background service that orchestrates the Telegram bot lifecycle with dual-mode transport support.
/// Supports long polling (hardened with security mitigations) and webhook modes.
/// </summary>
public sealed class TelegramBotService : BackgroundService
{
    private readonly ITelegramBotClient _botClient;
    private readonly TelegramSecurityConfig _config;
    private readonly ITelegramAuthGuard _authGuard;
    private readonly ITelegramCommandRouter _router;
    private readonly ITelegramSessionBridge _sessionBridge;
    // Note: _streamer will be wired into HandleSessionCommandAsync in future work
    // Currently, session command handling sends placeholder acknowledgments
    #pragma warning disable IDE0052 // Remove unread private members - will be used for response streaming
    private readonly ITelegramResponseStreamer _streamer;
    #pragma warning restore IDE0052
    private readonly ISessionManager _sessionManager;
    private readonly IHostApplicationLifetime _hostLifetime;
    private readonly ILogger<TelegramBotService> _logger;
    private readonly PollingLockFile? _pollingLock;

    // Long polling configuration
    private const int InitialBackoffSeconds = 5;
    private const int MaxRetryBackoffSeconds = 120;
    private const int MaxConsecutiveFailures = 10;

    private int _consecutiveFailures;
    private int _currentBackoffSeconds = InitialBackoffSeconds;
    private int _lastProcessedUpdateId;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramBotService"/> class.
    /// </summary>
    /// <param name="config">The Telegram security configuration.</param>
    /// <param name="authGuard">The authentication guard for validating updates.</param>
    /// <param name="router">The command router for routing updates.</param>
    /// <param name="sessionBridge">The session bridge for managing Telegram sessions.</param>
    /// <param name="streamer">The response streamer for sending responses to Telegram.</param>
    /// <param name="sessionManager">The session manager for lifecycle operations.</param>
    /// <param name="hostLifetime">The host application lifetime for shutdown coordination.</param>
    /// <param name="secretsProvider">The secrets provider for loading the bot token.</param>
    /// <param name="logger">The logger.</param>
    /// <exception cref="InvalidOperationException">Thrown when bot token is not found in ISecretsProvider or environment variable.</exception>
    public TelegramBotService(
        TelegramSecurityConfig config,
        ITelegramAuthGuard authGuard,
        ITelegramCommandRouter router,
        ITelegramSessionBridge sessionBridge,
        ITelegramResponseStreamer streamer,
        ISessionManager sessionManager,
        IHostApplicationLifetime hostLifetime,
        ISecretsProvider secretsProvider,
        ILogger<TelegramBotService> logger)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(authGuard);
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(sessionBridge);
        ArgumentNullException.ThrowIfNull(streamer);
        ArgumentNullException.ThrowIfNull(sessionManager);
        ArgumentNullException.ThrowIfNull(hostLifetime);
        ArgumentNullException.ThrowIfNull(secretsProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _config = config;
        _authGuard = authGuard;
        _router = router;
        _sessionBridge = sessionBridge;
        _streamer = streamer;
        _sessionManager = sessionManager;
        _hostLifetime = hostLifetime;
        _logger = logger;

        // Load bot token from ISecretsProvider or environment variable (fail-fast)
        var botToken = LoadBotToken(secretsProvider);

        // Create bot client with TLS 1.2+ enforcement (T14 mitigation)
        // Note: HttpClient ownership is transferred to TelegramBotClient
#pragma warning disable CA2000 // TelegramBotClient takes ownership of HttpClient and will dispose it
        _botClient = new TelegramBotClient(botToken, CreateSecureHttpClient());
#pragma warning restore CA2000

        // Acquire single-instance lock for long polling mode (T15 mitigation)
        if (_config.Mode == TelegramTransportMode.LongPolling)
        {
            _pollingLock = new PollingLockFile();
            if (!_pollingLock.TryAcquire())
            {
                _pollingLock.Dispose();
                throw new InvalidOperationException(
                    "Another instance of the Telegram bot is already running and polling. " +
                    "Only one instance can poll the same bot token simultaneously. " +
                    "Stop the other instance or use webhook mode instead.");
            }

            _logger.LogInformation("Acquired single-instance polling lock");
        }
    }

    /// <summary>
    /// Executes the Telegram bot service lifecycle.
    /// </summary>
    /// <param name="stoppingToken">Cancellation token to signal shutdown.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Telegram bot service starting in {Mode} mode", _config.Mode);

        try
        {
            if (_config.Mode == TelegramTransportMode.LongPolling)
            {
                await RunLongPollingLoopAsync(stoppingToken).ConfigureAwait(false);
            }
            else if (_config.Mode == TelegramTransportMode.Webhook)
            {
                await RunWebhookModeAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Telegram bot service stopped due to cancellation");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Telegram bot service encountered an unhandled exception");
            throw;
        }
        finally
        {
            _pollingLock?.Release();
            _logger.LogInformation("Telegram bot service stopped");
        }
    }

    /// <summary>
    /// Runs the long polling loop with hardened security mitigations.
    /// </summary>
    private async Task RunLongPollingLoopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting long polling loop with timeout {TimeoutSeconds}s", _config.PollingTimeoutSeconds);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // Poll for updates
                var updates = await _botClient.GetUpdates(
                    offset: _lastProcessedUpdateId + 1,
                    timeout: _config.PollingTimeoutSeconds,
                    allowedUpdates: [UpdateType.Message, UpdateType.CallbackQuery],
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                if (updates.Length == 0)
                {
                    // No updates, reset backoff on successful poll
                    if (_consecutiveFailures > 0)
                    {
                        _consecutiveFailures = 0;
                        _currentBackoffSeconds = InitialBackoffSeconds;
                        _logger.LogInformation("Polling resumed successfully, backoff reset");
                    }

                    continue;
                }

                // Kill switch priority: check for /killswitch BEFORE processing any other command
                // Use normalized command detection to handle @BotName mentions in group chats
                var killSwitchUpdate = updates.FirstOrDefault(u => IsKillSwitchCommand(u.Message?.Text));

                bool killSwitchExecuted = false;
                if (killSwitchUpdate is not null)
                {
                    _logger.LogCritical("Kill switch command detected in batch, processing immediately");
                    
                    // Validate and process kill switch - only exit if it was actually executed
                    var authResult = await _authGuard.ValidateAsync(killSwitchUpdate, cancellationToken).ConfigureAwait(false);
                    if (authResult.IsValid)
                    {
                        var routeResult = await _router.RouteAsync(killSwitchUpdate, authResult, cancellationToken).ConfigureAwait(false);
                        if (routeResult.Routed && routeResult.Command == TelegramCommand.KillSwitch)
                        {
                            await HandleKillSwitchAsync(authResult.ChatId, cancellationToken).ConfigureAwait(false);
                            killSwitchExecuted = true;
                            
                            // Commit offset for kill switch before exiting
                            // Make one more poll to confirm the offset with Telegram
                            _lastProcessedUpdateId = killSwitchUpdate.Id;
                            try
                            {
                                await _botClient.GetUpdates(
                                    offset: _lastProcessedUpdateId + 1,
                                    timeout: 0,
                                    cancellationToken: cancellationToken).ConfigureAwait(false);
                            }
#pragma warning disable CA1031 // Ignore all errors during final offset confirmation before shutdown
                            catch
#pragma warning restore CA1031
                            {
                                // Ignore errors during final offset confirmation
                            }
                            
                            // Exit polling loop - app shutdown initiated
                            return;
                        }
                    }
                }

                // Process updates sequentially
                foreach (var update in updates)
                {
                    // Skip kill switch if already processed
                    if (killSwitchUpdate is not null && update.Id == killSwitchUpdate.Id && killSwitchExecuted)
                    {
                        continue;
                    }

                    var success = await ProcessUpdateAsync(update, cancellationToken).ConfigureAwait(false);
                    
                    // Commit offset AFTER successful processing (offset-after-processing mitigation)
                    // Only advance if processing succeeded to allow retry on transient failures
                    if (success)
                    {
                        _lastProcessedUpdateId = update.Id;
                    }
                    else
                    {
                        _logger.LogWarning("Update {UpdateId} processing failed, will retry on next poll", update.Id);
                        break; // Stop processing this batch, will retry failed update and remaining updates
                    }
                }

                // Reset backoff on successful batch processing
                if (_consecutiveFailures > 0)
                {
                    _consecutiveFailures = 0;
                    _currentBackoffSeconds = InitialBackoffSeconds;
                    _logger.LogInformation("Polling resumed successfully after failures, backoff reset");
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown, don't count as failure
                throw;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _consecutiveFailures++;
                _logger.LogError(ex, "Polling error (consecutive failures: {Count})", _consecutiveFailures);

                // Stop polling after max consecutive failures
                if (_consecutiveFailures >= MaxConsecutiveFailures)
                {
                    _logger.LogCritical(
                        "Reached maximum consecutive failures ({Max}), stopping polling loop",
                        MaxConsecutiveFailures);
                    break;
                }

                // Exponential backoff with cap
                var delaySeconds = Math.Min(_currentBackoffSeconds, MaxRetryBackoffSeconds);
                _logger.LogWarning("Backing off for {Seconds}s before retry", delaySeconds);

                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken).ConfigureAwait(false);

                // Double the backoff for next failure (exponential)
                _currentBackoffSeconds = Math.Min(_currentBackoffSeconds * 2, MaxRetryBackoffSeconds);
            }
        }

        _logger.LogInformation("Long polling loop exited");
    }

    /// <summary>
    /// Checks if a message text represents the kill switch command.
    /// Handles @BotName mentions in group chats by normalizing the command.
    /// </summary>
    private bool IsKillSwitchCommand(string? messageText)
    {
        if (string.IsNullOrWhiteSpace(messageText))
        {
            return false;
        }

        var trimmed = messageText.Trim();

        // Fast path: exact match
        if (trimmed.Equals(_config.PanicCommand, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var panicCommand = _config.PanicCommand?.Trim() ?? string.Empty;
        if (panicCommand.Length == 0)
        {
            return false;
        }

        // Extract command token (before any arguments or whitespace)
        var spaceIndex = trimmed.IndexOf(' ', StringComparison.Ordinal);
        var commandToken = spaceIndex >= 0 ? trimmed[..spaceIndex] : trimmed;

        // Strip optional @BotName mention (e.g., "/killswitch@MyBot" -> "/killswitch")
        var atIndex = commandToken.IndexOf('@', StringComparison.Ordinal);
        if (atIndex >= 0)
        {
            commandToken = commandToken[..atIndex];
        }

        return commandToken.Equals(panicCommand, StringComparison.OrdinalIgnoreCase);
    }

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

            case TelegramCommand.Status:
            case TelegramCommand.Sessions:
            case TelegramCommand.Budget:
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

    /// <summary>
    /// Runs webhook mode (placeholder for initial implementation).
    /// </summary>
    private Task RunWebhookModeAsync(CancellationToken cancellationToken)
    {
        _logger.LogWarning("Webhook mode is not yet implemented. The bot will not process updates.");
        
        // Placeholder: keep service running but do nothing
        return Task.Delay(Timeout.Infinite, cancellationToken);
    }

    /// <summary>
    /// Loads the bot token from ISecretsProvider or environment variable.
    /// </summary>
    /// <param name="secretsProvider">The secrets provider.</param>
    /// <returns>The bot token.</returns>
    /// <exception cref="InvalidOperationException">Thrown when token is not found in either source.</exception>
    private string LoadBotToken(ISecretsProvider secretsProvider)
    {
        // Try ISecretsProvider first (Windows Credential Manager)
        var token = secretsProvider.GetSecret("KRUTAKA_TELEGRAM_BOT_TOKEN");

        // Fall back to environment variable
        token ??= Environment.GetEnvironmentVariable("KRUTAKA_TELEGRAM_BOT_TOKEN");

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException(
                "Telegram bot token not found. " +
                "Please store it in Windows Credential Manager (key: KRUTAKA_TELEGRAM_BOT_TOKEN) " +
                "or set the KRUTAKA_TELEGRAM_BOT_TOKEN environment variable.");
        }

        _logger.LogInformation("Bot token loaded successfully");
        return token;
    }

    /// <summary>
    /// Creates an HttpClient with TLS 1.2+ enforcement (T14 mitigation).
    /// </summary>
#pragma warning disable CA5398 // TLS 1.2+ is explicitly required per security spec (T14 mitigation in TELEGRAM.md)
#pragma warning disable CA2000 // HttpClient ownership is transferred to TelegramBotClient, which will dispose it
    private static HttpClient CreateSecureHttpClient()
    {
        var handler = new HttpClientHandler
        {
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CheckCertificateRevocationList = true // CA5399: Enable certificate revocation checking
        };

        // TelegramBotClient takes ownership of HttpClient and will dispose the handler
        return new HttpClient(handler);
    }
#pragma warning restore CA2000
#pragma warning restore CA5398

    /// <summary>
    /// Disposes the service and releases the polling lock.
    /// </summary>
    public override void Dispose()
    {
        _pollingLock?.Dispose();
        base.Dispose();
    }
}
