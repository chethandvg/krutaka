using System.Security;

namespace Krutaka.Tools;

/// <summary>
/// Provides secure file path validation and operations.
/// Prevents path traversal, blocks access to sensitive directories and files.
/// </summary>
public static class SafeFileOperations
{
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
    /// Maximum file size allowed for read operations (1 MB).
    /// </summary>
    public const long MaxFileSizeBytes = 1_048_576;

    /// <summary>
    /// Validates a file path for read or write access.
    /// Performs canonicalization and checks against blocked directories and patterns.
    /// </summary>
    /// <param name="path">The path to validate (can be relative or absolute).</param>
    /// <param name="allowedRoot">The allowed root directory (project root).</param>
    /// <returns>The canonicalized, validated absolute path.</returns>
    /// <exception cref="SecurityException">Thrown if the path violates security policy.</exception>
    public static string ValidatePath(string path, string allowedRoot)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(allowedRoot);

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new SecurityException("Path cannot be empty.");
        }

        if (string.IsNullOrWhiteSpace(allowedRoot))
        {
            throw new SecurityException("Allowed root cannot be empty.");
        }

        // Canonicalize the allowed root
        var canonicalRoot = Path.GetFullPath(allowedRoot);

        // Block UNC paths
        if (path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            throw new SecurityException($"UNC paths are not permitted: '{path}'");
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
            throw new SecurityException($"Invalid path: '{path}'. {ex.Message}", ex);
        }

        // Verify the path starts with the allowed root (prevents path traversal)
        if (!canonicalPath.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException(
                $"Path traversal detected: '{path}' resolves to '{canonicalPath}' which is outside the allowed root '{canonicalRoot}'");
        }

        // Check for blocked directories
        // Note: On Windows, these are exact path prefixes. On Linux, these Windows paths become
        // relative and get combined with projectRoot, so they won't match - but path traversal
        // check already blocks paths outside projectRoot, which provides the security guarantee.
        foreach (var blockedDir in BlockedDirectories)
        {
            // Check if canonicalPath starts with or contains the blocked directory
            if (canonicalPath.Contains(blockedDir, StringComparison.OrdinalIgnoreCase))
            {
                // Additional check: ensure it's a directory component, not just a substring
                // by checking for path separator after the blocked directory name
                var index = canonicalPath.IndexOf(blockedDir, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    var afterBlocked = index + blockedDir.Length;
                    // If it's at the end of the path, or followed by a separator, it's a real directory
                    if (afterBlocked >= canonicalPath.Length ||
                        canonicalPath[afterBlocked] == Path.DirectorySeparatorChar ||
                        canonicalPath[afterBlocked] == Path.AltDirectorySeparatorChar)
                    {
                        throw new SecurityException(
                            $"Access to '{blockedDir}' is not permitted: '{canonicalPath}'");
                    }
                }
            }
        }

        // Check for AppData directories
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        
        if (!string.IsNullOrEmpty(appDataPath) && 
            canonicalPath.StartsWith(appDataPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException(
                $"Access to AppData is not permitted: '{canonicalPath}'");
        }

        if (!string.IsNullOrEmpty(localAppDataPath) && 
            canonicalPath.StartsWith(localAppDataPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException(
                $"Access to LocalAppData is not permitted: '{canonicalPath}'");
        }

        // Block access to agent's own config directory
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var krutakaConfigPath = Path.Combine(userProfile, ".krutaka");
        if (canonicalPath.StartsWith(krutakaConfigPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException(
                $"Access to Krutaka configuration directory is not permitted: '{canonicalPath}'");
        }

        // Check for blocked file patterns
        var fileName = Path.GetFileName(canonicalPath);
        foreach (var pattern in BlockedFilePatterns)
        {
            if (fileName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
            {
                throw new SecurityException(
                    $"Access to files matching pattern '{pattern}' is not permitted: '{fileName}'");
            }
        }

        // Check for blocked file extensions
        var extension = Path.GetExtension(canonicalPath);
        if (!string.IsNullOrEmpty(extension))
        {
            foreach (var blockedExt in BlockedFileExtensions)
            {
                if (extension.Equals(blockedExt, StringComparison.OrdinalIgnoreCase))
                {
                    throw new SecurityException(
                        $"Access to '{blockedExt}' files is not permitted: '{fileName}'");
                }
            }
        }

        // Check for .env.* pattern (e.g., .env.local, .env.production)
        if (fileName.StartsWith(".env.", StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException(
                $"Access to .env configuration files is not permitted: '{fileName}'");
        }

        return canonicalPath;
    }

    /// <summary>
    /// Validates that a file size does not exceed the maximum allowed size.
    /// </summary>
    /// <param name="filePath">The file path to check.</param>
    /// <exception cref="SecurityException">Thrown if the file exceeds the size limit.</exception>
    public static void ValidateFileSize(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        if (!File.Exists(filePath))
        {
            return; // File doesn't exist yet (for write operations)
        }

        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > MaxFileSizeBytes)
        {
            throw new SecurityException(
                $"File size ({fileInfo.Length} bytes) exceeds maximum allowed size ({MaxFileSizeBytes} bytes): '{filePath}'");
        }
    }
}
