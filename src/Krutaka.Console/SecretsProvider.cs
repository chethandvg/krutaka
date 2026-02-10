using Meziantou.Framework.Win32;

namespace Krutaka.Console;

/// <summary>
/// Provides secure API key storage using Windows Credential Manager (DPAPI-backed).
/// </summary>
internal static class SecretsProvider
{
    private const string CredentialTargetName = "Krutaka_ApiKey";
    private const string ApiKeyPrefix = "sk-ant-";

    /// <summary>
    /// Stores the API key securely in Windows Credential Manager.
    /// </summary>
    /// <param name="apiKey">The Anthropic API key to store.</param>
    /// <exception cref="ArgumentNullException">Thrown when apiKey is null or whitespace.</exception>
    /// <exception cref="ArgumentException">Thrown when apiKey doesn't match the required pattern.</exception>
    public static void WriteCredential(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new ArgumentNullException(nameof(apiKey), "API key cannot be null or empty.");
        }

        if (!IsValidApiKey(apiKey))
        {
            throw new ArgumentException(
                $"API key must start with '{ApiKeyPrefix}'. Please provide a valid Anthropic API key.",
                nameof(apiKey));
        }

        CredentialManager.WriteCredential(
            applicationName: CredentialTargetName,
            userName: "Krutaka",
            secret: apiKey,
            comment: "Anthropic API key for Krutaka AI agent",
            persistence: CredentialPersistence.LocalMachine);
    }

    /// <summary>
    /// Retrieves the API key from Windows Credential Manager.
    /// </summary>
    /// <returns>The stored API key.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the API key is not found in Credential Manager.</exception>
    public static string ReadCredential()
    {
        var credential = CredentialManager.ReadCredential(CredentialTargetName);

        if (credential?.Password == null)
        {
            throw new InvalidOperationException(
                $"API key not found in Windows Credential Manager. " +
                $"Please run the setup wizard to configure your Anthropic API key. " +
                $"Expected credential name: '{CredentialTargetName}'");
        }

        return credential.Password;
    }

    /// <summary>
    /// Checks if an API key exists in Windows Credential Manager.
    /// </summary>
    /// <returns>True if the API key exists, otherwise false.</returns>
    public static bool HasStoredCredential()
    {
        var credential = CredentialManager.ReadCredential(CredentialTargetName);
        return credential?.Password != null;
    }

    /// <summary>
    /// Validates that an API key matches the required pattern.
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
}
