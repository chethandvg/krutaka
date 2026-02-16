using System.Collections.Concurrent;
using Krutaka.Core;
using Telegram.Bot.Types;

namespace Krutaka.Telegram;

/// <summary>
/// Implementation of <see cref="ITelegramAuthGuard"/> that validates Telegram updates
/// against user allowlist, rate limits, lockout status, anti-replay, and input validation.
/// </summary>
public sealed class TelegramAuthGuard : ITelegramAuthGuard
{
    private readonly TelegramSecurityConfig _config;
    private readonly IAuditLogger _auditLogger;
    private readonly ICorrelationContextAccessor _correlationAccessor;

    // User allowlist for O(1) lookup
    private readonly HashSet<long> _allowedUserIds;

    // User configuration lookup for role information
    private readonly Dictionary<long, TelegramUserConfig> _userConfigs;

    // Rate limiting: per-user sliding window counters
    private readonly ConcurrentDictionary<long, SlidingWindowCounter> _rateLimiters = new();

    // Lockout tracking: per-user lockout state
    private readonly ConcurrentDictionary<long, LockoutState> _lockoutStates = new();

    // Anti-replay: track last processed update_id globally
    private int _lastProcessedUpdateId;

    // Rate limit window duration in milliseconds (Environment.TickCount64 returns milliseconds)
    private readonly long _rateLimitWindowTicks;

    // Lockout duration in milliseconds
    private readonly long _lockoutDurationTicks;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramAuthGuard"/> class.
    /// </summary>
    /// <param name="config">The Telegram security configuration.</param>
    /// <param name="auditLogger">The audit logger.</param>
    /// <param name="correlationAccessor">The correlation context accessor.</param>
    public TelegramAuthGuard(
        TelegramSecurityConfig config,
        IAuditLogger auditLogger,
        ICorrelationContextAccessor correlationAccessor)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(auditLogger);
        ArgumentNullException.ThrowIfNull(correlationAccessor);

        _config = config;
        _auditLogger = auditLogger;
        _correlationAccessor = correlationAccessor;

        // Build allowlist and user config lookup
        _allowedUserIds = [.. config.AllowedUsers.Select(u => u.UserId)];
        _userConfigs = config.AllowedUsers.ToDictionary(u => u.UserId, u => u);

        // Pre-calculate durations in milliseconds (Environment.TickCount64 returns milliseconds)
        _rateLimitWindowTicks = (long)TimeSpan.FromMinutes(1).TotalMilliseconds;
        _lockoutDurationTicks = (long)config.LockoutDurationValue.TotalMilliseconds;

        _lastProcessedUpdateId = 0;
    }

    /// <inheritdoc/>
    public Task<AuthResult> ValidateAsync(Update update, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(update);
        cancellationToken.ThrowIfCancellationRequested();

        // Extract user ID and chat ID
        var userId = update.Message?.From?.Id ?? update.CallbackQuery?.From?.Id ?? 0;
        var chatId = update.Message?.Chat?.Id ?? update.CallbackQuery?.Message?.Chat?.Id ?? 0;
        var updateId = update.Id;

        // Get correlation context (or create a temporary one if not available)
        var correlationContext = _correlationAccessor.Current ?? new CorrelationContext();

        // Check 1: User allowlist
        if (!_allowedUserIds.Contains(userId))
        {
            var reason = "User not in allowlist";

            // Log authentication failure
            _auditLogger.LogTelegramAuth(correlationContext, new TelegramAuthEvent
            {
                SessionId = correlationContext.SessionId,
                TurnId = correlationContext.TurnId,
                TelegramUserId = userId,
                TelegramChatId = chatId,
                Outcome = AuthOutcome.Denied,
                DeniedReason = reason,
                UpdateId = updateId,
                Timestamp = DateTimeOffset.UtcNow
            });

            // Log security incident for unknown user attempt
            _auditLogger.LogTelegramSecurityIncident(correlationContext, new TelegramSecurityIncidentEvent
            {
                SessionId = correlationContext.SessionId,
                TurnId = correlationContext.TurnId,
                TelegramUserId = userId,
                Type = IncidentType.UnknownUserAttempt,
                Details = $"Unknown user {userId} attempted access from chat {chatId}",
                Timestamp = DateTimeOffset.UtcNow
            });

            // Silent drop - no reply sent to unknown users
            return Task.FromResult(AuthResult.Invalid(reason, userId, chatId));
        }

        // Get user role
        var userRole = _userConfigs[userId].Role;

        // Get or create lockout state for this user
        var lockoutState = _lockoutStates.GetOrAdd(userId, _ => new LockoutState());

        var currentTicks = Environment.TickCount64;

        // Check 2: Lockout status
        if (lockoutState.IsLockedOut(currentTicks))
        {
            var reason = "User locked out";

            // Log authentication failure
            _auditLogger.LogTelegramAuth(correlationContext, new TelegramAuthEvent
            {
                SessionId = correlationContext.SessionId,
                TurnId = correlationContext.TurnId,
                TelegramUserId = userId,
                TelegramChatId = chatId,
                Outcome = AuthOutcome.LockedOut,
                DeniedReason = reason,
                UpdateId = updateId,
                Timestamp = DateTimeOffset.UtcNow
            });

            return Task.FromResult(AuthResult.Invalid(reason, userId, chatId));
        }

        // Clear lockout if it has expired (IsLockedOut returned false)
        if (lockoutState.LockoutExpiresAtTicks > 0 && currentTicks >= lockoutState.LockoutExpiresAtTicks)
        {
            lockoutState.ClearLockout();
        }

        // Check 3: Rate limiting (sliding window)
        var rateLimiter = _rateLimiters.GetOrAdd(userId, _ => new SlidingWindowCounter());
        var commandCount = rateLimiter.AddAndGetCount(currentTicks, _rateLimitWindowTicks);

        if (commandCount > _config.MaxCommandsPerMinute)
        {
            var reason = "Rate limit exceeded";

            // Log rate limit event
            _auditLogger.LogTelegramRateLimit(correlationContext, new TelegramRateLimitEvent
            {
                SessionId = correlationContext.SessionId,
                TurnId = correlationContext.TurnId,
                TelegramUserId = userId,
                CommandCount = commandCount,
                LimitPerMinute = _config.MaxCommandsPerMinute,
                WindowDuration = TimeSpan.FromMinutes(1),
                Timestamp = DateTimeOffset.UtcNow
            });

            // Log authentication failure
            _auditLogger.LogTelegramAuth(correlationContext, new TelegramAuthEvent
            {
                SessionId = correlationContext.SessionId,
                TurnId = correlationContext.TurnId,
                TelegramUserId = userId,
                TelegramChatId = chatId,
                Outcome = AuthOutcome.RateLimited,
                DeniedReason = reason,
                UpdateId = updateId,
                Timestamp = DateTimeOffset.UtcNow
            });

            // Increment failed attempts and check for lockout
            var failedAttempts = lockoutState.IncrementFailedAttempts();
            if (failedAttempts >= _config.MaxFailedAuthAttempts)
            {
                lockoutState.TriggerLockout(currentTicks, _lockoutDurationTicks);

                // Log security incident for lockout
                _auditLogger.LogTelegramSecurityIncident(correlationContext, new TelegramSecurityIncidentEvent
                {
                    SessionId = correlationContext.SessionId,
                    TurnId = correlationContext.TurnId,
                    TelegramUserId = userId,
                    Type = IncidentType.LockoutTriggered,
                    Details = $"User {userId} locked out after {failedAttempts} failed attempts",
                    Timestamp = DateTimeOffset.UtcNow
                });
            }

            return Task.FromResult(AuthResult.Invalid(reason, userId, chatId));
        }

        // Check 4: Anti-replay (update_id must be greater than last processed)
        // Use CAS loop to maintain monotonic watermark (only advance, never go backwards)
        while (true)
        {
            var lastProcessed = Volatile.Read(ref _lastProcessedUpdateId);

            // Check if this is a replay attempt
            if (updateId <= lastProcessed)
            {
                var reason = "Replay attempt detected";

                // Log security incident for replay attempt
                _auditLogger.LogTelegramSecurityIncident(correlationContext, new TelegramSecurityIncidentEvent
                {
                    SessionId = correlationContext.SessionId,
                    TurnId = correlationContext.TurnId,
                    TelegramUserId = userId,
                    Type = IncidentType.ReplayAttempt,
                    Details = $"Replay attempt: update_id {updateId} <= last processed {lastProcessed}",
                    Timestamp = DateTimeOffset.UtcNow
                });

                // Log authentication failure
                _auditLogger.LogTelegramAuth(correlationContext, new TelegramAuthEvent
                {
                    SessionId = correlationContext.SessionId,
                    TurnId = correlationContext.TurnId,
                    TelegramUserId = userId,
                    TelegramChatId = chatId,
                    Outcome = AuthOutcome.Denied,
                    DeniedReason = reason,
                    UpdateId = updateId,
                    Timestamp = DateTimeOffset.UtcNow
                });

                return Task.FromResult(AuthResult.Invalid(reason, userId, chatId));
            }

            // Try to advance the watermark atomically (CAS only succeeds if no other thread updated it)
            var original = Interlocked.CompareExchange(ref _lastProcessedUpdateId, updateId, lastProcessed);
            if (original == lastProcessed)
            {
                // Successfully updated - this update is accepted
                break;
            }
            // If CAS failed, another thread updated the watermark - retry the loop
        }

        // Check 5: Input validation (message length)
        var messageText = update.Message?.Text ?? update.CallbackQuery?.Data ?? string.Empty;
        if (messageText.Length > _config.MaxInputMessageLength)
        {
            var reason = $"Message too long ({messageText.Length} > {_config.MaxInputMessageLength})";

            // Log authentication failure
            _auditLogger.LogTelegramAuth(correlationContext, new TelegramAuthEvent
            {
                SessionId = correlationContext.SessionId,
                TurnId = correlationContext.TurnId,
                TelegramUserId = userId,
                TelegramChatId = chatId,
                Outcome = AuthOutcome.Denied,
                DeniedReason = reason,
                UpdateId = updateId,
                Timestamp = DateTimeOffset.UtcNow
            });

            return Task.FromResult(AuthResult.Invalid(reason, userId, chatId));
        }

        // All checks passed - clear lockout state if any
        if (lockoutState.FailedAttempts > 0)
        {
            lockoutState.ClearLockout();
        }

        // Log successful authentication
        _auditLogger.LogTelegramAuth(correlationContext, new TelegramAuthEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = userId,
            TelegramChatId = chatId,
            Outcome = AuthOutcome.Allowed,
            DeniedReason = null,
            UpdateId = updateId,
            Timestamp = DateTimeOffset.UtcNow
        });

        return Task.FromResult(AuthResult.Valid(userId, chatId, userRole));
    }
}
