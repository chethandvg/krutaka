namespace Krutaka.Tools;

/// <summary>
/// Scrubs sensitive environment variables before spawning child processes.
/// Removes API keys, secrets, tokens, and cloud provider credentials.
/// </summary>
public static class EnvironmentScrubber
{
    private static readonly string[] SensitiveSuffixes =
    [
        "_KEY", "_SECRET", "_TOKEN", "_PASSWORD"
    ];

    private static readonly string[] SensitivePrefixes =
    [
        "ANTHROPIC_",
        "AWS_",
        "AZURE_",
        "GCP_",
        "GOOGLE_"
    ];

    /// <summary>
    /// Scrubs sensitive environment variables from a dictionary.
    /// </summary>
    /// <param name="environment">The environment variable dictionary to scrub.</param>
    /// <returns>A new dictionary with sensitive variables removed.</returns>
    public static IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        var scrubbed = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in environment)
        {
            if (IsSensitiveVariable(kvp.Key))
            {
                // Skip sensitive variables
                continue;
            }

            scrubbed[kvp.Key] = kvp.Value;
        }

        return scrubbed;
    }

    /// <summary>
    /// Determines if an environment variable name is sensitive and should be scrubbed.
    /// </summary>
    /// <param name="variableName">The environment variable name.</param>
    /// <returns>True if the variable is sensitive, false otherwise.</returns>
    private static bool IsSensitiveVariable(string variableName)
    {
        if (string.IsNullOrWhiteSpace(variableName))
        {
            return false;
        }

        var upperName = variableName.ToUpperInvariant();

        // Check for sensitive suffixes
        if (SensitiveSuffixes.Any(suffix => upperName.EndsWith(suffix, StringComparison.Ordinal)))
        {
            return true;
        }

        // Check for sensitive prefixes
        if (SensitivePrefixes.Any(prefix => upperName.StartsWith(prefix, StringComparison.Ordinal)))
        {
            return true;
        }

        return false;
    }
}
