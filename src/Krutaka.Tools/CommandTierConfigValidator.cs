using System.Buffers;
using Krutaka.Core;
using Microsoft.Extensions.Logging;

namespace Krutaka.Tools;

/// <summary>
/// Validates command tier override configuration at application startup.
/// Enforces security boundaries to prevent configuration tampering attacks.
/// </summary>
public sealed partial class CommandTierConfigValidator
{
    private readonly ILogger<CommandTierConfigValidator>? _logger;

    // Shell metacharacters that could be used for injection attacks
    // Note: Backslash is intentionally excluded here as it's checked separately as a path separator
    private static readonly SearchValues<char> ShellMetacharacters =
        SearchValues.Create(['|', '>', '<', '&', ';', '`', '$', '%', '^', '!', '(', ')', '{', '}', '[', ']', '\'', '"', '\n', '\r', ':', '*', '?']);

    // Path separators that indicate executable is not a simple name
    private static readonly SearchValues<char> PathSeparators =
        SearchValues.Create([System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar, '/']);

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandTierConfigValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for warnings about borderline configurations.</param>
    public CommandTierConfigValidator(ILogger<CommandTierConfigValidator>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Validates a collection of tier override rules against security constraints.
    /// </summary>
    /// <param name="rules">The tier override rules to validate.</param>
    /// <returns>A validation result indicating success or failure with error messages.</returns>
    /// <exception cref="ArgumentNullException">Thrown when rules is null.</exception>
    public ValidationResult ValidateRules(CommandRiskRule[] rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        var errors = new List<string>();
        var warnings = new List<string>();

        foreach (var rule in rules)
        {
            var result = ValidateRule(rule);
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
                LogConfigWarning(_logger, warning, null);
            }
        }

        return new ValidationResult(errors.Count == 0, errors, warnings);
    }

    /// <summary>
    /// Validates a single tier override rule against security constraints.
    /// </summary>
    /// <param name="rule">The rule to validate.</param>
    /// <returns>A validation result indicating success or failure with error messages.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Instance member for consistency with ValidateRules and potential future logger usage")]
    public ValidationResult ValidateRule(CommandRiskRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var errors = new List<string>();
        var warnings = new List<string>();

        // 1. Validate executable is not null/empty/whitespace
        if (string.IsNullOrWhiteSpace(rule.Executable))
        {
            errors.Add("Tier override rule has empty or null executable name.");
            return new ValidationResult(false, errors, warnings);
        }

        var executable = rule.Executable.Trim();

        // 2. CRITICAL: Prevent promoting blocklisted commands
        // BlockedExecutables are Dangerous-tier and can NEVER be promoted via config
        if (CommandPolicy.BlockedExecutables.Contains(executable))
        {
            errors.Add($"Cannot override tier for blocklisted executable '{executable}'. " +
                      $"Dangerous-tier commands cannot be promoted via configuration for security reasons.");
            return new ValidationResult(false, errors, warnings);
        }

        // 3. CRITICAL: Users cannot add to the Dangerous tier via config (code-only change)
        if (rule.Tier == CommandRiskTier.Dangerous)
        {
            errors.Add($"Cannot set tier to 'Dangerous' for executable '{executable}'. " +
                      $"Adding commands to the blocklist must be done in code, not configuration.");
            return new ValidationResult(false, errors, warnings);
        }

        // 4. Validate executable is a simple name (no path separators)
        if (executable.IndexOfAny(PathSeparators) >= 0)
        {
            errors.Add($"Executable '{executable}' contains path separators. " +
                      $"Only simple executable names are allowed (e.g., 'cargo', not 'C:\\Tools\\cargo.exe').");
            return new ValidationResult(false, errors, warnings);
        }

        // 5. Validate executable doesn't contain shell metacharacters
        if (executable.IndexOfAny(ShellMetacharacters) >= 0)
        {
            errors.Add($"Executable '{executable}' contains shell metacharacters. " +
                      $"Executable names must be simple alphanumeric names.");
            return new ValidationResult(false, errors, warnings);
        }

        // 6. Validate argument patterns don't contain shell metacharacters
        if (rule.ArgumentPatterns != null)
        {
            foreach (var pattern in rule.ArgumentPatterns)
            {
                if (string.IsNullOrWhiteSpace(pattern))
                {
                    errors.Add($"Tier override rule for '{executable}' has empty or null argument pattern.");
                    return new ValidationResult(false, errors, warnings);
                }

                if (pattern.IndexOfAny(ShellMetacharacters) >= 0)
                {
                    errors.Add($"Argument pattern '{pattern}' for executable '{executable}' contains shell metacharacters. " +
                              $"Patterns must be simple alphanumeric strings.");
                    return new ValidationResult(false, errors, warnings);
                }
            }
        }
        else
        {
            // 7. WARN: Null argument patterns mean the rule applies to ANY arguments for this executable
            // This is broad and could be risky depending on the executable
            warnings.Add($"Tier override for '{executable}' has null argument patterns, which matches ALL arguments for this executable. " +
                        $"Consider using specific argument patterns to reduce the attack surface.");
        }

        return new ValidationResult(true, errors, warnings);
    }

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Warning,
        Message = "Command tier configuration warning: {Warning}")]
    private static partial void LogConfigWarning(ILogger logger, string warning, Exception? exception);
}
