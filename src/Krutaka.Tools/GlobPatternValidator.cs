using Microsoft.Extensions.Logging;

namespace Krutaka.Tools;

/// <summary>
/// Validates glob patterns for auto-grant directory access at startup.
/// Prevents overly broad patterns and enforces security boundaries.
/// </summary>
public sealed class GlobPatternValidator
{
    private readonly ILogger<GlobPatternValidator>? _logger;

    // Blocked directories - mirrors SafeFileOperations.BlockedDirectories for system paths
    // AppData, LocalAppData, and .krutaka are validated separately via SpecialFolder checks
    private static readonly string[] BlockedDirectories =
    [
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "System32",
        "SysWOW64"
    ];

    // LoggerMessage delegate for performance (CA1848)
    private static readonly Action<ILogger, string, Exception?> LogPatternWarning =
        LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(1, nameof(ValidatePatterns)),
            "{WarningMessage}");

    /// <summary>
    /// Initializes a new instance of the <see cref="GlobPatternValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for warnings about borderline patterns.</param>
    public GlobPatternValidator(ILogger<GlobPatternValidator>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Validates a collection of glob patterns against security constraints.
    /// </summary>
    /// <param name="patterns">The patterns to validate.</param>
    /// <param name="ceilingDirectory">The ceiling directory - patterns must be under this directory.</param>
    /// <returns>A validation result indicating success or failure with error messages.</returns>
    /// <exception cref="ArgumentNullException">Thrown when patterns is null.</exception>
    /// <exception cref="ArgumentException">Thrown when ceilingDirectory is null, empty, or whitespace.</exception>
    public ValidationResult ValidatePatterns(string[] patterns, string ceilingDirectory)
    {
        ArgumentNullException.ThrowIfNull(patterns);
        ArgumentException.ThrowIfNullOrWhiteSpace(ceilingDirectory);

        var errors = new List<string>();
        var warnings = new List<string>();

        foreach (var pattern in patterns)
        {
            var result = ValidatePattern(pattern, ceilingDirectory);
            if (!result.IsValid)
            {
                errors.AddRange(result.Errors);
            }

            warnings.AddRange(result.Warnings);
        }

        // Log warnings using explicit filtering
        if (_logger != null)
        {
            foreach (var warning in warnings.Where(w => !string.IsNullOrEmpty(w)))
            {
                LogPatternWarning(_logger, warning, null);
            }
        }

        return new ValidationResult(errors.Count == 0, errors, warnings);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Instance member for consistency with ValidatePatterns")]
    /// <summary>
    /// Validates a single glob pattern against security constraints.
    /// </summary>
    /// <param name="pattern">The pattern to validate.</param>
    /// <param name="ceilingDirectory">The ceiling directory - pattern must be under this directory.</param>
    /// <returns>A validation result indicating success or failure with error messages.</returns>
    public ValidationResult ValidatePattern(string pattern, string ceilingDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ceilingDirectory);

        var errors = new List<string>();
        var warnings = new List<string>();

        // Check for empty, null, or whitespace patterns
        if (string.IsNullOrWhiteSpace(pattern))
        {
            errors.Add("Glob pattern cannot be null, empty, or whitespace.");
            return new ValidationResult(false, errors, warnings);
        }

        // Normalize the pattern for validation
        var normalizedPattern = pattern.Replace('/', Path.DirectorySeparatorChar);

        // Check for blocked system directories in the pattern (before segment counting)
        foreach (var blockedDir in BlockedDirectories)
        {
            if (ContainsBlockedDirectory(normalizedPattern, blockedDir))
            {
                errors.Add($"Glob pattern '{pattern}' contains blocked directory '{blockedDir}'.");
                return new ValidationResult(false, errors, warnings);
            }
        }

        // Check for AppData, LocalAppData, and .krutaka directories using SpecialFolder paths
        if (CheckSpecialFolderPaths(normalizedPattern, out var specialFolderError))
        {
            errors.Add(specialFolderError);
            return new ValidationResult(false, errors, warnings);
        }

        // Check if pattern is outside ceiling directory (before segment counting)
        try
        {
            var canonicalCeiling = Path.GetFullPath(ceilingDirectory);

            // Extract the base path from the pattern (before any wildcards)
            var patternBase = ExtractBasePath(normalizedPattern);

            if (!string.IsNullOrEmpty(patternBase))
            {
                var canonicalBase = Path.GetFullPath(patternBase);

                // Check if the pattern's base is under the ceiling
                if (!IsPathUnderDirectory(canonicalBase, canonicalCeiling))
                {
                    errors.Add($"Glob pattern '{pattern}' is outside the ceiling directory '{ceilingDirectory}'.");
                    return new ValidationResult(false, errors, warnings);
                }
            }
            else
            {
                // Pattern is entirely wildcards (e.g., "**/something") - too broad
                errors.Add($"Glob pattern '{pattern}' must have an absolute base path (cannot start with wildcards).");
                return new ValidationResult(false, errors, warnings);
            }
        }
#pragma warning disable CA1031 // Do not catch general exception types - need to handle all path validation failures
        catch (Exception ex)
        {
            errors.Add($"Invalid glob pattern '{pattern}': {ex.Message}");
            return new ValidationResult(false, errors, warnings);
        }
#pragma warning restore CA1031

        // Count path segments for breadth validation
        // Extract the base path (before wildcards) and count its segments
        var basePattern = ExtractBasePath(normalizedPattern);
        var segments = basePattern
            .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries)
            .Where(s => !string.IsNullOrEmpty(s))
            .ToArray();

        // Reject overly broad patterns (fewer than 3 segments in base path)
        // Note: On Windows, "C:\Users\Name\**" has segments ["C:", "Users", "Name"] = 3
        //       On Linux, "/home/user/**" has segments ["home", "user"] = 2 (but should be 3 including root)
        // We need to count the root as a segment on Unix systems
        var segmentCount = segments.Length;
        if (!OperatingSystem.IsWindows() && basePattern.StartsWith(Path.DirectorySeparatorChar))
        {
            segmentCount++; // Count the root "/" as a segment on Unix
        }

        if (segmentCount < 3)
        {
            errors.Add($"Glob pattern '{pattern}' is too broad (fewer than 3 path segments). Example of valid pattern: 'C:\\Users\\name\\Projects\\**'");
            return new ValidationResult(false, errors, warnings);
        }

        // Warn about patterns with fewer than 4 segments
        if (segmentCount < 4)
        {
            warnings.Add($"Glob pattern '{pattern}' has only {segmentCount} segments - consider using a more specific pattern to reduce attack surface.");
        }

        return new ValidationResult(true, errors, warnings);
    }

    /// <summary>
    /// Checks if a pattern contains a blocked directory as a path component.
    /// Uses component-boundary matching to avoid false positives.
    /// </summary>
    private static bool ContainsBlockedDirectory(string pattern, string blockedDir)
    {
        // Use component-boundary matching for all blocked directories
        var index = pattern.IndexOf(blockedDir, StringComparison.OrdinalIgnoreCase);
        while (index >= 0)
        {
            // Ensure the match starts at a directory boundary (or at the very start)
            var isAtComponentStart = index == 0 ||
                pattern[index - 1] == Path.DirectorySeparatorChar ||
                pattern[index - 1] == Path.AltDirectorySeparatorChar;

            if (isAtComponentStart)
            {
                var afterBlocked = index + blockedDir.Length;
                // Ensure the match ends at a directory boundary (or at the very end)
                var isAtComponentEnd = afterBlocked >= pattern.Length ||
                    pattern[afterBlocked] == Path.DirectorySeparatorChar ||
                    pattern[afterBlocked] == Path.AltDirectorySeparatorChar;

                if (isAtComponentEnd)
                {
                    return true;
                }
            }

            // Look for any additional occurrences
            index = pattern.IndexOf(blockedDir, index + blockedDir.Length, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    /// <summary>
    /// Checks if a pattern targets AppData, LocalAppData, or .krutaka directories
    /// using actual SpecialFolder paths for accurate detection.
    /// </summary>
    private static bool CheckSpecialFolderPaths(string pattern, out string errorMessage)
    {
        errorMessage = string.Empty;

        // Extract the base path for validation (absolute part before wildcards)
        var basePath = ExtractBasePath(pattern);
        if (string.IsNullOrEmpty(basePath))
        {
            return false; // Cannot validate patterns without absolute base
        }

        try
        {
            var canonicalBase = Path.GetFullPath(basePath);

            // Check AppData
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            if (!string.IsNullOrEmpty(appDataPath) && IsPathUnderDirectory(canonicalBase, appDataPath))
            {
                errorMessage = $"Glob pattern '{pattern}' targets AppData directory which is not permitted.";
                return true;
            }

            // Check LocalAppData
            var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (!string.IsNullOrEmpty(localAppDataPath) && IsPathUnderDirectory(canonicalBase, localAppDataPath))
            {
                errorMessage = $"Glob pattern '{pattern}' targets LocalAppData directory which is not permitted.";
                return true;
            }

            // Check .krutaka config directory
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(userProfile))
            {
                var krutakaConfigPath = Path.Combine(userProfile, ".krutaka");
                if (IsPathUnderDirectory(canonicalBase, krutakaConfigPath))
                {
                    errorMessage = $"Glob pattern '{pattern}' targets .krutaka configuration directory which is not permitted.";
                    return true;
                }
            }
        }
#pragma warning disable CA1031 // Do not catch general exception types - path validation errors should not fail the check
        catch
        {
            // If we can't validate the path, allow it (will be caught by other validation)
            return false;
        }
#pragma warning restore CA1031

        return false;
    }

    /// <summary>
    /// Extracts the base path from a glob pattern (the portion before any wildcards).
    /// </summary>
    private static string ExtractBasePath(string pattern)
    {
        // Find the first occurrence of * or **
        var wildcardIndex = pattern.IndexOf('*', StringComparison.Ordinal);
        if (wildcardIndex < 0)
        {
            return pattern; // No wildcards - entire pattern is the base
        }

        // Get everything before the wildcard
        var basePath = pattern[..wildcardIndex].TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return basePath;
    }

    /// <summary>
    /// Checks if a path is under a directory (including exact match).
    /// Uses case-insensitive comparison on Windows, case-sensitive on other platforms.
    /// </summary>
    private static bool IsPathUnderDirectory(string path, string directory)
    {
        var normalizedPath = Path.GetFullPath(path);
        var normalizedDirectory = Path.GetFullPath(directory);

        // Use OS-appropriate comparison
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        // Ensure directory ends with separator for proper prefix checking
        if (!normalizedDirectory.EndsWith(Path.DirectorySeparatorChar))
        {
            normalizedDirectory += Path.DirectorySeparatorChar;
        }

        var normalizedDirectoryTrimmed = normalizedDirectory.TrimEnd(Path.DirectorySeparatorChar);

        return normalizedPath.StartsWith(normalizedDirectory, comparison) ||
               string.Equals(normalizedPath, normalizedDirectoryTrimmed, comparison);
    }
}

/// <summary>
/// Represents the result of glob pattern validation.
/// </summary>
public sealed class ValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the validation succeeded.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the validation errors.
    /// </summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>
    /// Gets the validation warnings.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ValidationResult"/> class.
    /// </summary>
    public ValidationResult(bool isValid, IReadOnlyList<string> errors, IReadOnlyList<string> warnings)
    {
        IsValid = isValid;
        Errors = errors;
        Warnings = warnings;
    }
}
