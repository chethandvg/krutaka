namespace Krutaka.Core;

/// <summary>
/// Abstraction for secure secrets storage and retrieval.
/// Implementations use platform-specific secure storage (e.g., Windows Credential Manager).
/// </summary>
public interface ISecretsProvider
{
    /// <summary>
    /// Retrieves a secret value by key.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <returns>The secret value, or null if not found.</returns>
    string? GetSecret(string key);

    /// <summary>
    /// Stores a secret value securely.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="value">The secret value.</param>
    void SetSecret(string key, string value);

    /// <summary>
    /// Checks if a secret exists.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <returns>True if the secret exists, otherwise false.</returns>
    bool HasSecret(string key);
}
