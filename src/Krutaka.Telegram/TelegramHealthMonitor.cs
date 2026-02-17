using System.Collections.Concurrent;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using Telegram.Bot;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

/// <summary>
/// Implementation of Telegram health monitoring with proactive notifications and rate limiting.
/// </summary>
public sealed class TelegramHealthMonitor : ITelegramHealthMonitor
{
    private readonly ITelegramBotClient _botClient;
    private readonly TelegramSecurityConfig _config;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<TelegramHealthMonitor> _logger;

    // Track which sessions have already been warned about budget to prevent duplicate warnings
    private readonly HashSet<Guid> _budgetWarnedSessions = [];

    // Rate limiting: (chatId, eventType) -> last notification time
    // Uses monotonic clock (Environment.TickCount64) for reliable timing
    private readonly ConcurrentDictionary<(long ChatId, string EventType), long> _lastNotificationTicks = new();

    // Rate limit: 1 notification per event type per chat per minute
    private const long RateLimitTicksPerMinute = 60 * 1000; // milliseconds

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramHealthMonitor"/> class.
    /// </summary>
    /// <param name="botClient">The Telegram bot client.</param>
    /// <param name="config">The Telegram security configuration (for admin user identification).</param>
    /// <param name="sessionManager">The session manager for checking active sessions.</param>
    /// <param name="logger">The logger.</param>
    public TelegramHealthMonitor(
        ITelegramBotClient botClient,
        TelegramSecurityConfig config,
        ISessionManager sessionManager,
        ILogger<TelegramHealthMonitor> logger)
    {
        ArgumentNullException.ThrowIfNull(botClient);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(sessionManager);
        ArgumentNullException.ThrowIfNull(logger);

        _botClient = botClient;
        _config = config;
        _sessionManager = sessionManager;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task NotifyStartupAsync(CancellationToken cancellationToken)
    {
        const string message = "🟢 Krutaka bot is online";
        await SendToAllAdminsAsync(message, "startup", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task NotifyShutdownAsync(CancellationToken cancellationToken)
    {
        const string message = "🔴 Krutaka bot is shutting down";
        await SendToAllAdminsAsync(message, "shutdown", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task NotifyErrorAsync(string errorSummary, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(errorSummary);

        // Sanitize error summary to remove sensitive data
        var sanitizedError = SanitizeErrorMessage(errorSummary);
        var message = $"⚠️ Error alert: {sanitizedError}";

        await SendToAllAdminsAsync(message, "error", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task NotifyTaskCompletedAsync(long chatId, string taskSummary, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(taskSummary);

        var message = $"✅ Task completed: {taskSummary}";
        await SendToSpecificChatAsync(chatId, message, "task_completed", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task NotifyBudgetWarningAsync(long chatId, SessionBudget budget, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(budget);

        var tokenUsagePercent = (budget.TokensUsed * 100.0) / budget.MaxTokens;
        var message = $"💰 Budget warning: {tokenUsagePercent:F1}% of token budget used ({budget.TokensUsed:N0}/{budget.MaxTokens:N0} tokens)";

        await SendToSpecificChatAsync(chatId, message, "budget_warning", cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async Task CheckBudgetThresholdsAsync(CancellationToken cancellationToken)
    {
        var sessions = _sessionManager.ListActiveSessions();

        foreach (var sessionSummary in sessions)
        {
            // Get the actual managed session to access budget
            var session = _sessionManager.GetSession(sessionSummary.SessionId);
            if (session is null)
            {
                continue; // Session may have been terminated since we listed it
            }

            // Check if budget exceeds 80% threshold
            var tokenUsagePercent = (session.Budget.TokensUsed * 100.0) / session.Budget.MaxTokens;
            if (tokenUsagePercent >= 80.0)
            {
                // Check if we've already warned about this session
                lock (_budgetWarnedSessions)
                {
                    if (_budgetWarnedSessions.Contains(session.SessionId))
                    {
                        continue; // Already warned, skip
                    }

                    // Mark as warned
                    _budgetWarnedSessions.Add(session.SessionId);
                }

                // Determine chat ID from external key (e.g., "telegram:123456789")
                if (session.ExternalKey is not null && session.ExternalKey.StartsWith("telegram:", StringComparison.Ordinal))
                {
                    var chatIdStr = session.ExternalKey["telegram:".Length..];
                    if (long.TryParse(chatIdStr, out var chatId))
                    {
                        await NotifyBudgetWarningAsync(chatId, session.Budget, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Sends a notification to all admin users.
    /// </summary>
    private async Task SendToAllAdminsAsync(string message, string eventType, CancellationToken cancellationToken)
    {
        var adminUsers = _config.AllowedUsers.Where(u => u.Role == TelegramUserRole.Admin);

        foreach (var admin in adminUsers)
        {
            try
            {
                // Admins identified by UserId, but we need chatId for sending messages
                // In Telegram, for private chats, chatId == userId
                var chatId = admin.UserId;

                // Check rate limit
                if (!ShouldSendNotification(chatId, eventType))
                {
                    _logger.LogDebug(
                        "Rate limit: skipping {EventType} notification to admin {UserId}",
                        eventType,
                        admin.UserId);
                    continue;
                }

                await _botClient.SendMessage(
                    chatId,
                    message,
                    cancellationToken: cancellationToken).ConfigureAwait(false);

                _logger.LogInformation(
                    "Sent {EventType} notification to admin {UserId}",
                    eventType,
                    admin.UserId);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(
                    ex,
                    "Failed to send {EventType} notification to admin {UserId}",
                    eventType,
                    admin.UserId);
            }
        }
    }

    /// <summary>
    /// Sends a notification to a specific chat.
    /// </summary>
    private async Task SendToSpecificChatAsync(
        long chatId,
        string message,
        string eventType,
        CancellationToken cancellationToken)
    {
        try
        {
            // Check rate limit
            if (!ShouldSendNotification(chatId, eventType))
            {
                _logger.LogDebug(
                    "Rate limit: skipping {EventType} notification to chat {ChatId}",
                    eventType,
                    chatId);
                return;
            }

            await _botClient.SendMessage(
                chatId,
                message,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "Sent {EventType} notification to chat {ChatId}",
                eventType,
                chatId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(
                ex,
                "Failed to send {EventType} notification to chat {ChatId}",
                eventType,
                chatId);
        }
    }

    /// <summary>
    /// Checks if a notification should be sent based on rate limiting.
    /// Rate limit: maximum 1 notification per event type per chat per minute.
    /// Uses monotonic clock (Environment.TickCount64) for reliable timing.
    /// </summary>
    /// <returns>True if notification should be sent; false if rate-limited.</returns>
    private bool ShouldSendNotification(long chatId, string eventType)
    {
        var key = (chatId, eventType);
        var now = Environment.TickCount64;

        // Try to get the last notification time
        if (_lastNotificationTicks.TryGetValue(key, out var lastTicks))
        {
            var elapsed = now - lastTicks;
            if (elapsed < RateLimitTicksPerMinute)
            {
                return false; // Rate limited
            }
        }

        // Update last notification time
        _lastNotificationTicks[key] = now;
        return true;
    }

    /// <summary>
    /// Sanitizes an error message to remove sensitive data (stack traces, file paths, tokens).
    /// </summary>
    private static string SanitizeErrorMessage(string errorMessage)
    {
        // Remove stack traces (lines starting with "at " or "   at ")
        var lines = errorMessage.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
        var sanitized = new List<string>();

        foreach (var line in lines)
        {
            var trimmed = line.Trim();

            // Skip stack trace lines
            if (trimmed.StartsWith("at ", StringComparison.Ordinal))
            {
                continue;
            }

            // Skip file path patterns (C:\, /home/, etc.)
            if (trimmed.Contains(":\\", StringComparison.Ordinal) ||
                trimmed.Contains("/home/", StringComparison.Ordinal) ||
                trimmed.Contains("/usr/", StringComparison.Ordinal) ||
                trimmed.Contains("/var/", StringComparison.Ordinal))
            {
                continue;
            }

            // Skip token-like patterns (long alphanumeric strings)
            if (System.Text.RegularExpressions.Regex.IsMatch(trimmed, @"[A-Za-z0-9]{32,}"))
            {
                continue;
            }

            sanitized.Add(trimmed);
        }

        // Join and truncate if too long
        var result = string.Join(" ", sanitized);
        if (result.Length > 200)
        {
            result = result[..197] + "...";
        }

        return string.IsNullOrWhiteSpace(result) ? "An error occurred" : result;
    }
}
