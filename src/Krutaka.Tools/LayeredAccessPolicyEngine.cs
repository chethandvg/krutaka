using System.Security;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Four-layer access policy engine that evaluates directory access requests.
/// Layers: Hard Deny → Configurable Allow → Session Grants → Heuristic Checks.
/// A denial at any layer is final and cannot be overridden by subsequent layers.
/// </summary>
public sealed class LayeredAccessPolicyEngine : IAccessPolicyEngine
{
    private readonly IFileOperations _fileOperations;
    private readonly string _ceilingDirectory;
    private readonly string[] _autoGrantPatterns;
    private readonly ISessionAccessStore? _sessionStore;

    // Blocked directories from SafeFileOperations (Layer 1 hard deny)
    private static readonly string[] HardDenyDirectories =
    [
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "System32",
        "SysWOW64"
    ];

    /// <summary>
    /// Initializes a new instance of the <see cref="LayeredAccessPolicyEngine"/> class.
    /// </summary>
    /// <param name="fileOperations">The file operations service for path validation.</param>
    /// <param name="ceilingDirectory">The maximum ancestor directory - agent cannot access anything above this.</param>
    /// <param name="autoGrantPatterns">Glob patterns for auto-approved directory access (Layer 2).</param>
    /// <param name="sessionStore">Optional session access store for Layer 3 grant checking.</param>
    public LayeredAccessPolicyEngine(
        IFileOperations fileOperations,
        string ceilingDirectory,
        string[] autoGrantPatterns,
        ISessionAccessStore? sessionStore = null)
    {
        _fileOperations = fileOperations ?? throw new ArgumentNullException(nameof(fileOperations));
        _ceilingDirectory = ceilingDirectory ?? throw new ArgumentNullException(nameof(ceilingDirectory));
        _autoGrantPatterns = autoGrantPatterns ?? throw new ArgumentNullException(nameof(autoGrantPatterns));
        _sessionStore = sessionStore;
    }

    /// <inheritdoc/>
    public async Task<AccessDecision> EvaluateAsync(DirectoryAccessRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Decision cache - local to this evaluation (thread-safe)
        var decisionCache = new Dictionary<string, AccessDecision>(StringComparer.OrdinalIgnoreCase);

        // Canonicalize and resolve the requested path
        string canonicalPath;
        try
        {
            canonicalPath = PathResolver.ResolveToFinalTarget(request.Path);
        }
        catch (SecurityException ex)
        {
            return AccessDecision.Deny($"Path resolution failed: {ex.Message}");
        }
#pragma warning disable CA1031 // Do not catch general exception types - need to handle all path resolution failures
        catch (Exception ex)
        {
            return AccessDecision.Deny($"Invalid path: {ex.Message}");
        }
#pragma warning restore CA1031

        // Check decision cache
        if (decisionCache.TryGetValue(canonicalPath, out var cachedDecision))
        {
            return cachedDecision;
        }

        // Layer 1: Hard Deny List (immutable - never changes)
        var layer1Result = EvaluateLayer1HardDeny(canonicalPath);
        if (layer1Result != null)
        {
            decisionCache[canonicalPath] = layer1Result;
            return layer1Result;
        }

        // Layer 2: Configurable Allow List (glob patterns)
        var layer2Result = EvaluateLayer2ConfigurableAllow(canonicalPath, request.Level);
        if (layer2Result != null)
        {
            decisionCache[canonicalPath] = layer2Result;
            return layer2Result;
        }

        // Layer 3: Session Grants (previously approved access)
        var layer3Result = await EvaluateLayer3SessionGrantsAsync(canonicalPath, request.Level, cancellationToken).ConfigureAwait(false);
        if (layer3Result != null)
        {
            decisionCache[canonicalPath] = layer3Result;
            return layer3Result;
        }

        // Layer 4: Heuristic Checks (cross-volume detection, path depth)
        var layer4Result = EvaluateLayer4Heuristics(canonicalPath, request.Level);
        decisionCache[canonicalPath] = layer4Result;
        return layer4Result;
    }

    /// <summary>
    /// Layer 1: Hard Deny List - System directories, UNC paths, paths above ceiling, ADS, device names.
    /// Returns null if path passes all hard deny checks.
    /// </summary>
    private AccessDecision? EvaluateLayer1HardDeny(string canonicalPath)
    {
        // Check UNC paths (already blocked by PathResolver, but double-check)
        if (canonicalPath.StartsWith("\\\\", StringComparison.Ordinal))
        {
            return AccessDecision.Deny("UNC paths are not permitted.");
        }

        // Check blocked system directories using component-boundary matching (like SafeFileOperations)
        foreach (var blockedDir in HardDenyDirectories.Where(d => !string.IsNullOrWhiteSpace(d)))
        {
            var index = canonicalPath.IndexOf(blockedDir, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                // Ensure the match starts at a directory boundary (or at the very start)
                var isAtComponentStart = index == 0 ||
                    canonicalPath[index - 1] == Path.DirectorySeparatorChar ||
                    canonicalPath[index - 1] == Path.AltDirectorySeparatorChar;

                if (isAtComponentStart)
                {
                    var afterBlocked = index + blockedDir.Length;
                    // Ensure the match ends at a directory boundary (or at the very end)
                    var isAtComponentEnd = afterBlocked >= canonicalPath.Length ||
                        canonicalPath[afterBlocked] == Path.DirectorySeparatorChar ||
                        canonicalPath[afterBlocked] == Path.AltDirectorySeparatorChar;

                    if (isAtComponentEnd)
                    {
                        return AccessDecision.Deny($"Access to '{blockedDir}' is not permitted.");
                    }
                }

                // Look for any additional occurrences of the blocked directory name
                index = canonicalPath.IndexOf(blockedDir, index + blockedDir.Length, StringComparison.OrdinalIgnoreCase);
            }
        }

        // Check AppData directories
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrEmpty(appDataPath) && IsPathUnderDirectory(canonicalPath, appDataPath))
        {
            return AccessDecision.Deny("Access to AppData is not permitted.");
        }

        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(localAppDataPath) && IsPathUnderDirectory(canonicalPath, localAppDataPath))
        {
            return AccessDecision.Deny("Access to LocalAppData is not permitted.");
        }

        // Check Krutaka config directory
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var krutakaConfigPath = Path.Combine(userProfile, ".krutaka");
        if (IsPathUnderDirectory(canonicalPath, krutakaConfigPath))
        {
            return AccessDecision.Deny("Access to Krutaka configuration directory is not permitted.");
        }

        // Check ceiling directory enforcement (cannot access above ceiling on same volume)
        // Cross-volume requests are deferred to Layer 4 for RequiresApproval
        var canonicalCeiling = Path.GetFullPath(_ceilingDirectory);
        var ceilingRoot = Path.GetPathRoot(canonicalCeiling);
        var pathRoot = Path.GetPathRoot(canonicalPath);

        if (!string.IsNullOrEmpty(ceilingRoot)
            && !string.IsNullOrEmpty(pathRoot)
            && string.Equals(ceilingRoot, pathRoot, StringComparison.OrdinalIgnoreCase))
        {
            // Same volume - enforce ceiling containment
            if (!IsPathUnderDirectory(canonicalPath, canonicalCeiling))
            {
                return AccessDecision.Deny($"Access above ceiling directory '{canonicalCeiling}' is not permitted.");
            }
        }

        // All hard deny checks passed
        return null;
    }

    /// <summary>
    /// Layer 2: Configurable Allow List - Glob pattern matching for auto-grant.
    /// Returns granted decision if pattern matches, null if no match.
    /// Uses custom glob matching with case-insensitive comparison on Windows.
    /// </summary>
    private AccessDecision? EvaluateLayer2ConfigurableAllow(string canonicalPath, AccessLevel requestedLevel)
    {
        if (_autoGrantPatterns.Length == 0)
        {
            return null; // No patterns configured
        }

        // Check each pattern for a match
        foreach (var pattern in _autoGrantPatterns)
        {
            if (string.IsNullOrWhiteSpace(pattern))
            {
                continue;
            }

            if (MatchesGlobPattern(canonicalPath, pattern))
            {
                return AccessDecision.Grant(canonicalPath, requestedLevel);
            }
        }

        return null; // No match - continue to next layer
    }

    /// <summary>
    /// Simple glob pattern matching. Supports ** for any subdirectory.
    /// Uses case-insensitive matching on Windows, case-sensitive on other platforms.
    /// </summary>
    private static bool MatchesGlobPattern(string path, string pattern)
    {
        // Normalize separators for comparison
        var normalizedPath = path.Replace('\\', '/');
        var normalizedPattern = pattern.Replace('\\', '/');

        // Use OS-appropriate comparison
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        // Handle ** (match any subdirectory)
        if (normalizedPattern.EndsWith("/**", StringComparison.Ordinal))
        {
            var basePattern = normalizedPattern[..^3]; // Remove /**

            // Allow match on the base directory itself, with or without trailing slash
            if (string.Equals(normalizedPath, basePattern, comparison) ||
                string.Equals(normalizedPath, basePattern + "/", comparison))
            {
                return true;
            }

            // For descendants, enforce a directory boundary after the base pattern
            var prefix = basePattern.EndsWith('/')
                ? basePattern
                : basePattern + "/";

            return normalizedPath.StartsWith(prefix, comparison);
        }

        // Exact match
        return string.Equals(normalizedPath, normalizedPattern, comparison);
    }

    /// <summary>
    /// Layer 3: Session Grants - Check if access was previously granted in this session.
    /// Returns granted decision if session grant exists, null if not found.
    /// </summary>
    private async Task<AccessDecision?> EvaluateLayer3SessionGrantsAsync(
        string canonicalPath,
        AccessLevel requestedLevel,
        CancellationToken cancellationToken)
    {
        if (_sessionStore == null)
        {
            return null; // No session store configured
        }

        var isGranted = await _sessionStore.IsGrantedAsync(canonicalPath, requestedLevel, cancellationToken).ConfigureAwait(false);
        if (isGranted)
        {
            return AccessDecision.Grant(canonicalPath, requestedLevel);
        }

        return null; // No session grant found
    }

    /// <summary>
    /// Layer 4: Heuristic Checks - Cross-volume detection, path depth analysis.
    /// Returns RequiresApproval or Denied based on heuristics.
    /// </summary>
    private AccessDecision EvaluateLayer4Heuristics(string canonicalPath, AccessLevel _ /* requestedLevel unused in v0.2.0-5 */)
    {
        // Cross-volume detection: check if path is on a different drive than ceiling
        var ceilingRoot = Path.GetPathRoot(_ceilingDirectory);
        var requestedRoot = Path.GetPathRoot(canonicalPath);

        if (!string.IsNullOrEmpty(ceilingRoot) &&
            !string.IsNullOrEmpty(requestedRoot) &&
            !string.Equals(ceilingRoot, requestedRoot, StringComparison.OrdinalIgnoreCase))
        {
            // Cross-volume access detected - flag for human approval
            return AccessDecision.RequireApproval(canonicalPath);
        }

        // Path depth heuristics: very deep nesting (>10 levels) might be suspicious
        var depth = canonicalPath.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries).Length;
        if (depth > 10)
        {
            // Very deep path - flag for human approval
            return AccessDecision.RequireApproval(canonicalPath);
        }

        // Default: require human approval for paths not matched by earlier layers
        return AccessDecision.RequireApproval(canonicalPath);
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
