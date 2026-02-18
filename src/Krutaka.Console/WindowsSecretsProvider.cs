using Krutaka.Core;

namespace Krutaka.Console;

/// <summary>
/// Windows Credential Manager implementation of ISecretsProvider.
/// Wraps the static SecretsProvider for dependency injection.
/// Supports multiple secret types: Claude API key, Telegram bot token.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via dependency injection")]
internal sealed class WindowsSecretsProvider : ISecretsProvider
{
    // Supported secret keys
    private const string ApiKeyName = "Krutaka_ApiKey";
    private const string ClaudeApiKey = "Claude:ApiKey";
    private const string TelegramBotTokenKey = "KRUTAKA_TELEGRAM_BOT_TOKEN";

    /// <inheritdoc />
    public string? GetSecret(string key)
    {
        // Claude API key
        if (key == ClaudeApiKey || key == ApiKeyName)
        {
            return SecretsProvider.HasStoredCredential()
                ? SecretsProvider.ReadCredential()
                : null;
        }

        // Telegram bot token
        if (key == TelegramBotTokenKey)
        {
            return SecretsProvider.HasStoredBotToken()
                ? SecretsProvider.ReadBotToken()
                : null;
        }

        return null;
    }

    /// <inheritdoc />
    public void SetSecret(string key, string value)
    {
        // Claude API key
        if (key == ClaudeApiKey || key == ApiKeyName)
        {
            SecretsProvider.WriteCredential(value);
            return;
        }

        // Telegram bot token
        if (key == TelegramBotTokenKey)
        {
            SecretsProvider.WriteBotToken(value);
            return;
        }

        throw new ArgumentException($"Unsupported secret key: {key}", nameof(key));
    }

    /// <inheritdoc />
    public bool HasSecret(string key)
    {
        // Claude API key
        if (key == ClaudeApiKey || key == ApiKeyName)
        {
            return SecretsProvider.HasStoredCredential();
        }

        // Telegram bot token
        if (key == TelegramBotTokenKey)
        {
            return SecretsProvider.HasStoredBotToken();
        }

        return false;
    }
}
