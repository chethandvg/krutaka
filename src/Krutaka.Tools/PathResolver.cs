using System.Security;

namespace Krutaka.Tools;

/// <summary>
/// Resolves file paths to their final target, handling symlinks, junctions, and reparse points.
/// Blocks Alternate Data Streams (ADS), reserved device names, and device path prefixes.
/// </summary>
public static class PathResolver
{
    private static readonly HashSet<string> ReservedDeviceNames =
    [
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    ];

    /// <summary>
    /// Resolves a path to its final target, following all symlinks, junctions, and reparse points.
    /// Validates against ADS, device names, and device path prefixes.
    /// </summary>
    /// <param name="path">The path to resolve.</param>
    /// <returns>The fully resolved canonical path.</returns>
    /// <exception cref="SecurityException">Thrown if path contains blocked patterns (ADS, device names, device prefixes).</exception>
    /// <exception cref="IOException">Thrown if circular symlink is detected.</exception>
    public static string ResolveToFinalTarget(string path)
    {
        ArgumentNullException.ThrowIfNull(path);

        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be empty or whitespace.", nameof(path));
        }

        // Block device path prefixes (\\.\, \\?\)
        if (path.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException($"Device path prefixes are not permitted: '{path}'");
        }

        // Canonicalize the path first
        string canonicalPath;
        try
        {
            canonicalPath = Path.GetFullPath(path);
        }
        catch (Exception ex)
        {
            throw new SecurityException($"Invalid path: '{path}'. {ex.Message}", ex);
        }

        // Check for Alternate Data Streams (ADS)
        if (ContainsAlternateDataStream(canonicalPath))
        {
            throw new SecurityException($"Alternate Data Streams (ADS) are not permitted: '{path}'");
        }

        // Check for reserved device names
        var fileName = Path.GetFileName(canonicalPath);
        if (!string.IsNullOrEmpty(fileName))
        {
            // Remove extension for device name check (e.g., CON.txt is also blocked)
            var nameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
            if (ReservedDeviceNames.Contains(nameWithoutExtension, StringComparer.OrdinalIgnoreCase))
            {
                throw new SecurityException($"Reserved device names are not permitted: '{fileName}'");
            }
        }

        // Resolve symlinks and junctions
        return ResolveSymlinksAndJunctions(canonicalPath);
    }

    /// <summary>
    /// Resolves all symlinks and junctions in the path to their final target.
    /// If the path doesn't exist, validates the parent directory chain instead.
    /// </summary>
    private static string ResolveSymlinksAndJunctions(string path)
    {
        var visitedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var currentPath = path;

        // Try to resolve the full path
        var resolvedPath = ResolvePathWithCircularDetection(currentPath, visitedPaths);
        if (resolvedPath != null)
        {
            return resolvedPath;
        }

        // Path doesn't exist - validate parent directory chain
        var directory = Path.GetDirectoryName(currentPath);
        if (string.IsNullOrEmpty(directory))
        {
            // No parent directory (e.g., root or relative path without parent)
            return currentPath;
        }

        // Recursively resolve parent directories
        visitedPaths.Clear();
        var resolvedParent = ResolvePathWithCircularDetection(directory, visitedPaths);
        if (resolvedParent != null)
        {
            // Reconstruct path with resolved parent and original filename
            var fileName = Path.GetFileName(currentPath);
            return Path.Combine(resolvedParent, fileName);
        }

        // Parent doesn't exist either - return canonical path as-is
        return currentPath;
    }

    /// <summary>
    /// Resolves a single path, following symlinks and junctions with circular link detection.
    /// Returns null if the path doesn't exist.
    /// </summary>
    private static string? ResolvePathWithCircularDetection(string path, HashSet<string> visitedPaths)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            return null;
        }

        var currentPath = path;

        while (true)
        {
            // Check for circular links
            if (!visitedPaths.Add(currentPath))
            {
                throw new IOException($"Circular symlink detected: '{path}'");
            }

            FileSystemInfo? linkTarget = null;

            try
            {
                // Note: We use returnFinalTarget: false and manually follow the chain in a loop
                // to enable circular link detection. Using returnFinalTarget: true would resolve
                // the entire chain at once but wouldn't allow us to detect cycles, potentially
                // causing infinite loops or exceptions in the .NET runtime.
                if (File.Exists(currentPath))
                {
                    var fileInfo = new FileInfo(currentPath);
                    linkTarget = fileInfo.ResolveLinkTarget(returnFinalTarget: false);
                }
                else if (Directory.Exists(currentPath))
                {
                    var dirInfo = new DirectoryInfo(currentPath);
                    linkTarget = dirInfo.ResolveLinkTarget(returnFinalTarget: false);
                }
            }
            catch (IOException)
            {
                // If ResolveLinkTarget fails (e.g., not a link, I/O error), treat as non-link
                break;
            }
            catch (UnauthorizedAccessException)
            {
                // If we don't have permission to resolve the link, treat as non-link
                break;
            }

            // Not a link or couldn't resolve - we're done
            if (linkTarget == null)
            {
                break;
            }

            // Follow the link
            currentPath = linkTarget.FullName;
        }

        return currentPath;
    }

    /// <summary>
    /// Checks if a path contains an Alternate Data Stream (ADS) indicator.
    /// ADS paths contain a colon (:) after the drive letter position.
    /// </summary>
    /// <param name="canonicalPath">The canonical (full) path to check.</param>
    /// <returns>True if the path contains ADS syntax, false otherwise.</returns>
    /// <remarks>
    /// Valid paths:
    /// - C:\path\file.txt (drive letter colon at position 1 is allowed)
    /// - /path/file.txt (Unix paths have no colons)
    /// 
    /// Invalid paths (ADS):
    /// - C:\path\file.txt:hidden (colon after the filename)
    /// - C:\path\file.txt:stream:$DATA (multiple ADS components)
    /// - file.txt:ads (relative path with ADS)
    /// </remarks>
    private static bool ContainsAlternateDataStream(string canonicalPath)
    {
        // Find the first colon in the path
#pragma warning disable CA1865 // Use char overload (char overload doesn't support StringComparison)
        var firstColonIndex = canonicalPath.IndexOf(":", StringComparison.Ordinal);
#pragma warning restore CA1865

        // If colon is at position 1, it's a drive letter (e.g., "C:")
        // Check if there's another colon after that
        if (firstColonIndex == 1)
        {
            // Drive letter colon is valid - check if there's another colon after it
#pragma warning disable CA1865 // Use char overload (char overload doesn't support StringComparison)
            return canonicalPath.Length > 2 && canonicalPath.IndexOf(":", 2, StringComparison.Ordinal) >= 0;
#pragma warning restore CA1865
        }

        // Any colon at position > 1 or position 0 is an ADS indicator
        return firstColonIndex >= 0;
    }
}
