using Meziantou.Framework.Win32;

namespace Krutaka.Console;

/// <summary>
/// Provides secure secret storage using Windows Credential Manager (DPAPI-backed).
/// Supports multiple credential types: Claude API key, Telegram bot token.
/// </summary>
internal static class SecretsProvider
{
    // Credential target names for different secret types
    private const string ApiKeyCredentialName = "Krutaka_ApiKey";
    private const string BotTokenCredentialName = "Krutaka_Telegram_BotToken";

    // Validation patterns
    private const string ApiKeyPrefix = "sk-ant-";

    /// <summary>
    /// Stores the Claude API key securely in Windows Credential Manager.
    /// </summary>
    /// <param name="apiKey">The Anthropic API key to store.</param>
    /// <exception cref="ArgumentNullException">Thrown when apiKey is null.</exception>
    /// <exception cref="ArgumentException">Thrown when apiKey is empty, whitespace, or doesn't match the required pattern.</exception>
    public static void WriteCredential(string apiKey)
    {
        if (apiKey is null)
        {
            throw new ArgumentNullException(nameof(apiKey), "API key cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentException("API key cannot be empty or whitespace.", nameof(apiKey));
        }

        if (!IsValidApiKey(apiKey))
        {
            throw new ArgumentException(
                $"API key must start with '{ApiKeyPrefix}'. Please provide a valid Anthropic API key.",
                nameof(apiKey));
        }

        CredentialManager.WriteCredential(
            applicationName: ApiKeyCredentialName,
            userName: "Krutaka",
            secret: apiKey,
            comment: "Anthropic API key for Krutaka AI agent",
            persistence: CredentialPersistence.LocalMachine);
    }

    /// <summary>
    /// Retrieves the Claude API key from Windows Credential Manager.
    /// </summary>
    /// <returns>The stored API key.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the API key is not found in Credential Manager.</exception>
    public static string ReadCredential()
    {
        var credential = CredentialManager.ReadCredential(ApiKeyCredentialName);

        if (credential?.Password == null)
        {
            throw new InvalidOperationException(
                $"API key not found in Windows Credential Manager. " +
                $"Please run the setup wizard to configure your Anthropic API key. " +
                $"Expected credential name: '{ApiKeyCredentialName}'");
        }

        return credential.Password;
    }

    /// <summary>
    /// Checks if a Claude API key exists in Windows Credential Manager.
    /// </summary>
    /// <returns>True if the API key exists, otherwise false.</returns>
    public static bool HasStoredCredential()
    {
        var credential = CredentialManager.ReadCredential(ApiKeyCredentialName);
        return credential?.Password != null;
    }

    /// <summary>
    /// Stores the Telegram bot token securely in Windows Credential Manager.
    /// </summary>
    /// <param name="botToken">The Telegram bot token to store.</param>
    /// <exception cref="ArgumentNullException">Thrown when botToken is null.</exception>
    /// <exception cref="ArgumentException">Thrown when botToken is empty, whitespace, or doesn't match the required pattern.</exception>
    public static void WriteBotToken(string botToken)
    {
        if (botToken is null)
        {
            throw new ArgumentNullException(nameof(botToken), "Bot token cannot be null.");
        }

        if (string.IsNullOrWhiteSpace(botToken))
        {
            throw new ArgumentException("Bot token cannot be empty or whitespace.", nameof(botToken));
        }

        if (!IsValidBotToken(botToken))
        {
            throw new ArgumentException(
                "Bot token must match the format 'digits:alphanumeric'. Please provide a valid Telegram bot token.",
                nameof(botToken));
        }

        CredentialManager.WriteCredential(
            applicationName: BotTokenCredentialName,
            userName: "Krutaka",
            secret: botToken,
            comment: "Telegram bot token for Krutaka AI agent",
            persistence: CredentialPersistence.LocalMachine);
    }

    /// <summary>
    /// Retrieves the Telegram bot token from Windows Credential Manager.
    /// </summary>
    /// <returns>The stored bot token.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the bot token is not found in Credential Manager.</exception>
    public static string ReadBotToken()
    {
        var credential = CredentialManager.ReadCredential(BotTokenCredentialName);

        if (credential?.Password == null)
        {
            throw new InvalidOperationException(
                $"Telegram bot token not found in Windows Credential Manager. " +
                $"Please store it using the setup wizard or console command. " +
                $"Expected credential name: '{BotTokenCredentialName}'");
        }

        return credential.Password;
    }

    /// <summary>
    /// Checks if a Telegram bot token exists in Windows Credential Manager.
    /// </summary>
    /// <returns>True if the bot token exists, otherwise false.</returns>
    public static bool HasStoredBotToken()
    {
        var credential = CredentialManager.ReadCredential(BotTokenCredentialName);
        return credential?.Password != null;
    }

    /// <summary>
    /// Validates that a Claude API key matches the required pattern.
    /// </summary>
    /// <param name="apiKey">The API key to validate.</param>
    /// <returns>True if the API key is valid, otherwise false.</returns>
    public static bool IsValidApiKey(string? apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return false;
        }

        return apiKey.StartsWith(ApiKeyPrefix, StringComparison.Ordinal);
    }

    /// <summary>
    /// Validates that a Telegram bot token matches the required pattern (digits:alphanumeric).
    /// Format: {bot_id}:{token} where bot_id is digits and token is alphanumeric.
    /// Example: "123456789:ABCdefGHIjklMNOpqrsTUVwxyz1234567890"
    /// </summary>
    /// <param name="botToken">The bot token to validate.</param>
    /// <returns>True if the bot token is valid, otherwise false.</returns>
    public static bool IsValidBotToken(string? botToken)
    {
        if (string.IsNullOrWhiteSpace(botToken))
        {
            return false;
        }

        var parts = botToken.Split(':', 2);
        if (parts.Length != 2)
        {
            return false;
        }

        // First part (bot_id) must be all digits
        var botId = parts[0];
        if (string.IsNullOrEmpty(botId) || !botId.All(char.IsDigit))
        {
            return false;
        }

        // Second part (token) must be alphanumeric (letters and digits only, no special chars)
        var token = parts[1];
        if (string.IsNullOrEmpty(token) || !token.All(c => char.IsLetterOrDigit(c) || c == '_' || c == '-'))
        {
            return false;
        }

        return true;
    }
}
