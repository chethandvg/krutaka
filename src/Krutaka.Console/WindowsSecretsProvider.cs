using Krutaka.Core;

namespace Krutaka.Console;

/// <summary>
/// Windows Credential Manager implementation of ISecretsProvider.
/// Wraps the static SecretsProvider for dependency injection.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via dependency injection")]
internal sealed class WindowsSecretsProvider : ISecretsProvider
{
    private const string ApiKeyName = "Krutaka_ApiKey";

    /// <inheritdoc />
    public string? GetSecret(string key)
    {
        // For now, only support the Claude API key
        if (key == "Claude:ApiKey" || key == ApiKeyName)
        {
            return SecretsProvider.HasStoredCredential()
                ? SecretsProvider.ReadCredential()
                : null;
        }

        return null;
    }

    /// <inheritdoc />
    public void SetSecret(string key, string value)
    {
        // For now, only support the Claude API key
        if (key == "Claude:ApiKey" || key == ApiKeyName)
        {
            SecretsProvider.WriteCredential(value);
        }
    }

    /// <inheritdoc />
    public bool HasSecret(string key)
    {
        // For now, only support the Claude API key
        if (key == "Claude:ApiKey" || key == ApiKeyName)
        {
            return SecretsProvider.HasStoredCredential();
        }

        return false;
    }
}
