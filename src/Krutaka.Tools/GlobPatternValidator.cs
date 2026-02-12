using Microsoft.Extensions.Logging;

namespace Krutaka.Tools;

/// <summary>
/// Validates glob patterns for auto-grant directory access at startup.
/// Prevents overly broad patterns and enforces security boundaries.
/// </summary>
public sealed class GlobPatternValidator
{
    private readonly ILogger<GlobPatternValidator>? _logger;

    // Blocked directories from SafeFileOperations (must match)
    private static readonly string[] BlockedDirectories =
    [
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "System32",
        "SysWOW64",
        "AppData",
        "LocalAppData",
        ".krutaka"
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
    /// <exception cref="ArgumentNullException">Thrown when patterns or ceilingDirectory is null.</exception>
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

        // Log warnings
        if (_logger != null)
        {
            foreach (var warning in warnings)
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

        // Check for blocked directories in the pattern (before segment counting)
        foreach (var blockedDir in BlockedDirectories)
        {
            if (ContainsBlockedDirectory(normalizedPattern, blockedDir))
            {
                errors.Add($"Glob pattern '{pattern}' contains blocked directory '{blockedDir}'.");
                return new ValidationResult(false, errors, warnings);
            }
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
    /// </summary>
    private static bool ContainsBlockedDirectory(string pattern, string blockedDir)
    {
        // Special handling for AppData and LocalAppData - check if they're anywhere in the path
        if (blockedDir == "AppData" || blockedDir == "LocalAppData")
        {
            return pattern.Contains(blockedDir, StringComparison.OrdinalIgnoreCase);
        }

        // For other blocked directories, use component-boundary matching
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
    /// Uses case-insensitive comparison on Windows.
    /// </summary>
    private static bool IsPathUnderDirectory(string path, string directory)
    {
        var normalizedPath = Path.GetFullPath(path);
        var normalizedDirectory = Path.GetFullPath(directory);

        // Ensure directory ends with separator for proper prefix checking
        if (!normalizedDirectory.EndsWith(Path.DirectorySeparatorChar))
        {
            normalizedDirectory += Path.DirectorySeparatorChar;
        }

        return normalizedPath.StartsWith(normalizedDirectory, StringComparison.OrdinalIgnoreCase) ||
               string.Equals(normalizedPath, normalizedDirectory.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
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
