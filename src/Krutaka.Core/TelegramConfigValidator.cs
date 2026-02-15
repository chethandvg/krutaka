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
    public static void Validate(TelegramSecurityConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        // Note: All validation is performed by the TelegramSecurityConfig record's
        // init-only property setters during construction.
        // This method exists for explicit validation calls and future extensibility.
        // The record's constructor will throw InvalidOperationException if any validation fails.

        // Additional validation beyond constructor checks can be added here if needed.
        // For now, if the config instance exists, it has passed all validations.
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
