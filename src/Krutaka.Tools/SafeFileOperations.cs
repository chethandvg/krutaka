using System.Security;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Provides secure file path validation and operations.
/// Prevents path traversal, blocks access to sensitive directories and files.
/// Logs security violations to the audit trail when audit logger is configured.
/// </summary>
public class SafeFileOperations : IFileOperations
{
    private readonly IAuditLogger? _auditLogger;

    // NOTE: Hardcoded Windows paths are intentional - this project targets Windows only (net10.0-windows)
    // On Linux/Mac, these paths won't match, but AppData checks below will handle platform-specific dirs
    private static readonly string[] BlockedDirectories =
    [
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "System32",
        "SysWOW64"
    ];

    private static readonly string[] BlockedFilePatterns =
    [
        ".env",
        ".credentials",
        ".secret",
        ".secrets",
        "id_rsa",
        "id_ed25519",
        "known_hosts",
        "authorized_keys"
    ];

    private static readonly string[] BlockedFileExtensions =
    [
        ".pfx", ".p12", ".key", ".pem", ".cer", ".crt", ".kdbx"
    ];

    /// <summary>
    /// Initializes a new instance of the <see cref="SafeFileOperations"/> class.
    /// </summary>
    /// <param name="auditLogger">Optional audit logger for security violation logging.</param>
    public SafeFileOperations(IAuditLogger? auditLogger = null)
    {
        _auditLogger = auditLogger;
    }

    /// <inheritdoc/>
    public long MaxFileSizeBytes => 1_048_576;

    /// <inheritdoc/>
    public string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(allowedRoot);

        if (string.IsNullOrWhiteSpace(path))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                "Path cannot be empty.",
                correlationContext);
        }

        if (string.IsNullOrWhiteSpace(allowedRoot))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                allowedRoot,
                "Allowed root cannot be empty.",
                correlationContext);
        }

        // Canonicalize the allowed root and ensure it ends with a separator for safe prefix checking
        var canonicalRoot = Path.GetFullPath(allowedRoot);
        if (!canonicalRoot.EndsWith(Path.DirectorySeparatorChar))
        {
            canonicalRoot += Path.DirectorySeparatorChar;
        }

        // Block UNC paths
        if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"UNC paths are not permitted: '{path}'",
                correlationContext);
        }

        // Combine with root if relative, or use as-is if absolute
        var combinedPath = Path.IsPathRooted(path)
            ? path
            : Path.Combine(canonicalRoot, path);

        // Canonicalize the combined path
        string canonicalPath;
        try
        {
            canonicalPath = Path.GetFullPath(combinedPath);
        }
        catch (Exception ex)
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Invalid path: '{path}'. {ex.Message}",
                correlationContext);
            throw; // Unreachable, but satisfies compiler
        }

        // Verify the path is within the allowed root (prevents path traversal and sibling directory access)
        // The canonicalRoot has a trailing separator, so we check:
        // 1. If canonicalPath starts with canonicalRoot (handles subdirectories)
        // 2. OR if canonicalPath equals canonicalRoot without the trailing separator (handles the root itself)
        var isWithinRoot = canonicalPath.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(canonicalPath, canonicalRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);

        if (!isWithinRoot)
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Path traversal detected: '{path}' resolves to '{canonicalPath}' which is outside the allowed root '{canonicalRoot.TrimEnd(Path.DirectorySeparatorChar)}'",
                correlationContext);
        }

        // Check for blocked directories
        foreach (var blockedDir in BlockedDirectories)
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
                        LogAndThrowSecurityViolation(
                            "blocked_path",
                            path,
                            $"Access to '{blockedDir}' is not permitted: '{canonicalPath}'",
                            correlationContext);
                    }
                }

                // Look for any additional occurrences of the blocked directory name
                index = canonicalPath.IndexOf(blockedDir, index + blockedDir.Length, StringComparison.OrdinalIgnoreCase);
            }
        }

        // Check for AppData directories
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        if (!string.IsNullOrEmpty(appDataPath) &&
            canonicalPath.StartsWith(appDataPath, StringComparison.OrdinalIgnoreCase))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Access to AppData is not permitted: '{canonicalPath}'",
                correlationContext);
        }

        if (!string.IsNullOrEmpty(localAppDataPath) &&
            canonicalPath.StartsWith(localAppDataPath, StringComparison.OrdinalIgnoreCase))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Access to LocalAppData is not permitted: '{canonicalPath}'",
                correlationContext);
        }

        // Block access to agent's own config directory
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var krutakaConfigPath = Path.Combine(userProfile, ".krutaka");
        if (canonicalPath.StartsWith(krutakaConfigPath, StringComparison.OrdinalIgnoreCase))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Access to Krutaka configuration directory is not permitted: '{canonicalPath}'",
                correlationContext);
        }

        // Check for blocked file patterns
        var fileName = Path.GetFileName(canonicalPath);
        var matchedPattern = BlockedFilePatterns
            .FirstOrDefault(pattern => fileName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase));

        if (matchedPattern != null)
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Access to files matching pattern '{matchedPattern}' is not permitted: '{fileName}'",
                correlationContext);
        }

        // Check for blocked file extensions
        var extension = Path.GetExtension(canonicalPath);
        if (!string.IsNullOrEmpty(extension))
        {
            var matchedExtension = BlockedFileExtensions
                .FirstOrDefault(blockedExt => extension.Equals(blockedExt, StringComparison.OrdinalIgnoreCase));

            if (matchedExtension != null)
            {
                LogAndThrowSecurityViolation(
                    "blocked_path",
                    path,
                    $"Access to '{matchedExtension}' files is not permitted: '{fileName}'",
                    correlationContext);
            }
        }

        // Check for .env.* pattern (e.g., .env.local, .env.production)
        if (fileName.StartsWith(".env.", StringComparison.OrdinalIgnoreCase))
        {
            LogAndThrowSecurityViolation(
                "blocked_path",
                path,
                $"Access to .env configuration files is not permitted: '{fileName}'",
                correlationContext);
        }

        return canonicalPath;
    }

    /// <inheritdoc/>
    public void ValidateFileSize(string filePath, CorrelationContext? correlationContext = null)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        if (!File.Exists(filePath))
        {
            return; // File doesn't exist yet (for write operations)
        }

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > MaxFileSizeBytes)
        {
            LogAndThrowSecurityViolation(
                "blocked_file_size",
                filePath,
                $"File size ({fileInfo.Length} bytes) exceeds maximum allowed size ({MaxFileSizeBytes} bytes): '{filePath}'",
                correlationContext);
        }
    }

    /// <summary>
    /// Logs a security violation to the audit trail and throws a SecurityException.
    /// </summary>
    private void LogAndThrowSecurityViolation(
        string violationType,
        string blockedValue,
        string message,
        CorrelationContext? correlationContext)
    {
        // Log the violation if audit logger is configured
        if (_auditLogger != null && correlationContext != null)
        {
            _auditLogger.LogSecurityViolation(
                correlationContext,
                violationType,
                blockedValue,
                message);
        }

        // Always throw the security exception
        throw new SecurityException(message);
    }
}
