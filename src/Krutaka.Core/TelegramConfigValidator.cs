namespace Krutaka.Core;

/// <summary>
/// Static validator for TelegramSecurityConfig with fail-fast startup validation.
/// </summary>
public static class TelegramConfigValidator
{
    /// <summary>
    /// Validates a TelegramSecurityConfig instance and throws InvalidOperationException on any validation failure.
    /// This method is designed for startup validation (fail-fast).
    /// </summary>
    /// <param name="config">The configuration to validate.</param>
    /// <exception cref="ArgumentNullException">Thrown when config is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when any validation rule is violated.</exception>
    /// <remarks>
    /// This method re-validates all invariants to catch instances that may have been modified
    /// via 'with' expressions or object initializers after construction.
    /// </remarks>
    public static void Validate(TelegramSecurityConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        // Re-validate all invariants to catch modifications via 'with' expressions or object initializers
        
        // Validate AllowedUsers
        if (config.AllowedUsers is null || config.AllowedUsers.Length == 0)
        {
            throw new InvalidOperationException(
                "AllowedUsers cannot be null or empty. At least one Telegram user must be configured. " +
                "If no users are allowed, the bot cannot operate.");
        }

        // Check for duplicate user IDs
        var duplicateUserIds = config.AllowedUsers
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

        // Validate numeric limits
        if (config.MaxCommandsPerMinute <= 0)
        {
            throw new InvalidOperationException(
                $"MaxCommandsPerMinute must be greater than 0. Received: {config.MaxCommandsPerMinute}");
        }

        if (config.MaxTokensPerHour <= 0)
        {
            throw new InvalidOperationException(
                $"MaxTokensPerHour must be greater than 0. Received: {config.MaxTokensPerHour}");
        }

        if (config.MaxFailedAuthAttempts <= 0)
        {
            throw new InvalidOperationException(
                $"MaxFailedAuthAttempts must be greater than 0. Received: {config.MaxFailedAuthAttempts}");
        }

        if (config.MaxInputMessageLength <= 0)
        {
            throw new InvalidOperationException(
                $"MaxInputMessageLength must be greater than 0. Received: {config.MaxInputMessageLength}");
        }

        if (config.PollingTimeoutSeconds <= 0)
        {
            throw new InvalidOperationException(
                $"PollingTimeoutSeconds must be greater than 0. Received: {config.PollingTimeoutSeconds}");
        }

        // Validate LockoutDuration
        if (config.LockoutDuration.HasValue && config.LockoutDuration.Value <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"LockoutDuration must be greater than TimeSpan.Zero. Received: {config.LockoutDuration.Value}");
        }

        // Validate Webhook mode
        if (config.Mode == TelegramTransportMode.Webhook && string.IsNullOrWhiteSpace(config.WebhookUrl))
        {
            throw new InvalidOperationException(
                "WebhookUrl is required when Mode is set to Webhook. " +
                "Either provide a valid WebhookUrl or use LongPolling mode.");
        }
    }

    /// <summary>
    /// Attempts to validate a TelegramSecurityConfig and returns a result indicating success or failure.
    /// </summary>
    /// <param name="config">The configuration to validate.</param>
    /// <param name="errorMessage">The error message if validation fails, otherwise null.</param>
    /// <returns>True if validation succeeds, false otherwise.</returns>
    public static bool TryValidate(TelegramSecurityConfig config, out string? errorMessage)
    {
        try
        {
            Validate(config);
            errorMessage = null;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentNullException or InvalidOperationException)
        {
            errorMessage = ex.Message;
            return false;
        }
    }
}
