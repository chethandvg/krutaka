namespace Krutaka.Core;

/// <summary>
/// Security configuration for Telegram bot integration.
/// All settings are validated at startup (fail-fast).
/// </summary>
/// <remarks>
/// Critical security rule: BotToken is NOT part of this configuration.
/// It must be loaded from ISecretsProvider (Windows Credential Manager) or environment variables.
/// </remarks>
/// <param name="AllowedUsers">Telegram user allowlist with roles. REQUIRED. Empty array = bot disabled at startup.</param>
/// <param name="RequireConfirmationForElevated">Whether elevated commands require confirmation. Default: true.</param>
/// <param name="MaxCommandsPerMinute">Per-user rate limit for commands. Default: 10.</param>
/// <param name="MaxTokensPerHour">Per-user token budget per hour. Default: 100,000.</param>
/// <param name="MaxFailedAuthAttempts">Lockout threshold for failed auth attempts. Default: 3.</param>
/// <param name="LockoutDuration">Duration of user lockout after failed attempts. Default: 1 hour.</param>
/// <param name="PanicCommand">Emergency shutdown command. Default: "/killswitch".</param>
/// <param name="MaxInputMessageLength">Maximum length of input messages in characters. Default: 4,000.</param>
/// <param name="Mode">Transport mode (LongPolling or Webhook). Default: LongPolling.</param>
/// <param name="WebhookUrl">Webhook URL (required only for Webhook mode). Default: null.</param>
/// <param name="PollingTimeoutSeconds">Long polling timeout in seconds. Default: 30.</param>
#pragma warning disable CA1054 // URI parameters should not be strings - webhook URL is stored as string in config
public record TelegramSecurityConfig(
    TelegramUserConfig[] AllowedUsers,
    bool RequireConfirmationForElevated = true,
    int MaxCommandsPerMinute = 10,
    int MaxTokensPerHour = 100_000,
    int MaxFailedAuthAttempts = 3,
    TimeSpan? LockoutDuration = null,
    string PanicCommand = "/killswitch",
    int MaxInputMessageLength = 4_000,
    TelegramTransportMode Mode = TelegramTransportMode.LongPolling,
    string? WebhookUrl = null,
    int PollingTimeoutSeconds = 30)
#pragma warning restore CA1054
{
    /// <summary>
    /// Gets the validated allowed users array.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when AllowedUsers is null or empty during construction.</exception>
#pragma warning disable CA1819 // Properties should not return arrays - this is configuration data
    public TelegramUserConfig[] AllowedUsers { get; init; } = ValidateAllowedUsers(AllowedUsers);
#pragma warning restore CA1819

    /// <summary>
    /// Gets the validated maximum commands per minute.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when MaxCommandsPerMinute is less than or equal to 0.</exception>
    public int MaxCommandsPerMinute { get; init; } = ValidatePositive(MaxCommandsPerMinute, nameof(MaxCommandsPerMinute));

    /// <summary>
    /// Gets the validated maximum tokens per hour.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when MaxTokensPerHour is less than or equal to 0.</exception>
    public int MaxTokensPerHour { get; init; } = ValidatePositive(MaxTokensPerHour, nameof(MaxTokensPerHour));

    /// <summary>
    /// Gets the validated maximum failed auth attempts.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when MaxFailedAuthAttempts is less than or equal to 0.</exception>
    public int MaxFailedAuthAttempts { get; init; } = ValidatePositive(MaxFailedAuthAttempts, nameof(MaxFailedAuthAttempts));

    /// <summary>
    /// Gets the validated lockout duration. Defaults to 1 hour if not specified.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when LockoutDuration is less than or equal to TimeSpan.Zero.</exception>
    public TimeSpan? LockoutDuration { get; init; } = ValidateLockoutDuration(LockoutDuration);
    
    /// <summary>
    /// Gets the lockout duration value, using the default of 1 hour if not specified.
    /// </summary>
    public TimeSpan LockoutDurationValue => LockoutDuration ?? TimeSpan.FromHours(1);

    /// <summary>
    /// Gets the validated maximum input message length.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when MaxInputMessageLength is less than or equal to 0.</exception>
    public int MaxInputMessageLength { get; init; } = ValidatePositive(MaxInputMessageLength, nameof(MaxInputMessageLength));

    /// <summary>
    /// Gets the validated polling timeout in seconds.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when PollingTimeoutSeconds is less than or equal to 0.</exception>
    public int PollingTimeoutSeconds { get; init; } = ValidatePositive(PollingTimeoutSeconds, nameof(PollingTimeoutSeconds));

    /// <summary>
    /// Gets the validated transport mode and webhook URL combination.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when Mode is Webhook and WebhookUrl is null or whitespace.</exception>
    public TelegramTransportMode Mode { get; init; } = ValidateMode(Mode, WebhookUrl);

    /// <summary>
    /// Gets the webhook URL.
    /// </summary>
#pragma warning disable CA1056 // URI properties should not be strings - webhook URL is stored as string in config
    public string? WebhookUrl { get; init; } = WebhookUrl;
#pragma warning restore CA1056

    private static TelegramUserConfig[] ValidateAllowedUsers(TelegramUserConfig[] allowedUsers)
    {
        if (allowedUsers is null || allowedUsers.Length == 0)
        {
            throw new InvalidOperationException(
                "AllowedUsers cannot be null or empty. At least one Telegram user must be configured. " +
                "If no users are allowed, the bot cannot operate.");
        }

        // Check for duplicate user IDs
        var duplicateUserIds = allowedUsers
            .GroupBy(u => u.UserId)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateUserIds.Count > 0)
        {
            var duplicateList = string.Join(", ", duplicateUserIds);
            throw new InvalidOperationException(
                $"Duplicate UserId values found in AllowedUsers: {duplicateList}. " +
                "Each Telegram user ID must appear exactly once.");
        }

        return allowedUsers;
    }

    private static int ValidatePositive(int value, string paramName)
    {
        if (value <= 0)
        {
            throw new InvalidOperationException(
                $"{paramName} must be greater than 0. Received: {value}");
        }

        return value;
    }

    private static TimeSpan? ValidateLockoutDuration(TimeSpan? lockoutDuration)
    {
        if (lockoutDuration.HasValue && lockoutDuration.Value <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"LockoutDuration must be greater than TimeSpan.Zero. Received: {lockoutDuration.Value}");
        }

        return lockoutDuration;
    }

    private static TelegramTransportMode ValidateMode(TelegramTransportMode mode, string? webhookUrl)
    {
        if (mode == TelegramTransportMode.Webhook && string.IsNullOrWhiteSpace(webhookUrl))
        {
            throw new InvalidOperationException(
                "WebhookUrl is required when Mode is set to Webhook. " +
                "Either provide a valid WebhookUrl or use LongPolling mode.");
        }

        return mode;
    }
}
