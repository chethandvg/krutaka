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

        // Check for reserved device names in ALL path segments
        // On Windows, reserved device names are invalid in any path component
        CheckForReservedDeviceNames(canonicalPath, path);

        // Resolve symlinks and junctions
        return ResolveSymlinksAndJunctions(canonicalPath);
    }

    /// <summary>
    /// Resolves all symlinks and junctions in the path to their final target.
    /// Walks each path segment from root to leaf, resolving any reparse points encountered.
    /// If the path doesn't exist, validates all existing ancestor directories.
    /// </summary>
    private static string ResolveSymlinksAndJunctions(string path)
    {
        var visitedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Normalize to full path
        var fullPath = Path.GetFullPath(path);
        
        // Try segment-by-segment resolution for existing paths
        var resolved = ResolvePathSegmentBySegment(fullPath, visitedPaths);
        if (resolved != null)
        {
            return resolved;
        }

        // Path doesn't exist - walk up to find nearest existing ancestor,
        // resolve it, then append remaining non-existent segments
        return ResolveNonExistentPath(fullPath, visitedPaths);
    }

    /// <summary>
    /// Resolves a path by walking each segment from root to leaf.
    /// Returns null if the path doesn't exist.
    /// </summary>
    private static string? ResolvePathSegmentBySegment(string fullPath, HashSet<string> visitedPaths)
    {
        var root = Path.GetPathRoot(fullPath) ?? string.Empty;
        var remaining = fullPath[root.Length..];

        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var segments = remaining.Split(separators, StringSplitOptions.RemoveEmptyEntries);

        // Start from the root (e.g., "C:\" on Windows, "/" on Unix)
        var resolvedPath = root.TrimEnd(separators);
        
        // On Unix, root is "/" which becomes empty after TrimEnd
        // Ensure we maintain the root separator for absolute paths
        if (string.IsNullOrEmpty(resolvedPath) && !string.IsNullOrEmpty(root))
        {
            resolvedPath = root;
        }

        for (var i = 0; i < segments.Length; i++)
        {
            var segment = segments[i];

            // Build the path up to this segment
            resolvedPath = Path.Combine(resolvedPath, segment);

            var currentSegmentPath = resolvedPath;

            // Check if this segment exists
            var existsAsFile = File.Exists(currentSegmentPath);
            var existsAsDir = Directory.Exists(currentSegmentPath);
            
            if (!existsAsFile && !existsAsDir)
            {
                // A component along the path does not exist
                return null;
            }

            // Check for circular links on this segment path
            if (!visitedPaths.Add(currentSegmentPath))
            {
                throw new IOException($"Circular symlink detected: '{fullPath}'");
            }

            FileSystemInfo? linkTarget = null;
            
            // Decide whether this segment should be treated as a file or directory
            // For the final segment, prefer file if it exists; otherwise treat as directory
            var isLastSegment = i == segments.Length - 1;

            try
            {
                if (isLastSegment && existsAsFile)
                {
                    var fileInfo = new FileInfo(currentSegmentPath);
                    linkTarget = fileInfo.ResolveLinkTarget(returnFinalTarget: false);
                }
                else if (existsAsDir)
                {
                    var dirInfo = new DirectoryInfo(currentSegmentPath);
                    linkTarget = dirInfo.ResolveLinkTarget(returnFinalTarget: false);
                }
                else if (existsAsFile)
                {
                    // Non-final file segment (unusual but possible)
                    var fileInfo = new FileInfo(currentSegmentPath);
                    linkTarget = fileInfo.ResolveLinkTarget(returnFinalTarget: false);
                }
            }
            catch (IOException)
            {
                // If ResolveLinkTarget fails (e.g., not a link, I/O error), treat as non-link
                linkTarget = null;
            }
            catch (UnauthorizedAccessException)
            {
                // If we don't have permission to resolve the link, treat as non-link
                linkTarget = null;
            }

            // Not a link or couldn't resolve - continue with remaining segments
            if (linkTarget == null)
            {
                continue;
            }

            // Follow the link target
            var targetFullPath = Path.GetFullPath(linkTarget.FullName);

            // Circular detection on the resolved target as well
            if (!visitedPaths.Add(targetFullPath))
            {
                throw new IOException($"Circular symlink detected: '{fullPath}'");
            }

            // Replace the current accumulated path with the link target
            // Any remaining segments will be appended to this target
            resolvedPath = targetFullPath.TrimEnd(separators);
        }

        return resolvedPath;
    }

    /// <summary>
    /// Resolves a non-existent path by finding the nearest existing ancestor,
    /// resolving that ancestor, then appending the remaining non-existent segments.
    /// </summary>
    /// <param name="fullPath">The full path to resolve.</param>
    /// <param name="visitedPaths">The set of visited paths (unused - kept for signature consistency).</param>
    /// <returns>The resolved path with non-existent segments appended.</returns>
#pragma warning disable IDE0060 // Remove unused parameter - kept for method signature consistency
    private static string ResolveNonExistentPath(string fullPath, HashSet<string> visitedPaths)
#pragma warning restore IDE0060
    {
        var remainingSegments = new List<string>();
        var currentPath = fullPath;

        while (true)
        {
            // If we've reached an existing file or directory, resolve it
            if (File.Exists(currentPath) || Directory.Exists(currentPath))
            {
                // Create a new visitedPaths set for the ancestor resolution
                // This avoids false circular-link detection from the failed initial resolution attempt
                var ancestorVisitedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var resolvedAncestor = ResolvePathSegmentBySegment(currentPath, ancestorVisitedPaths);
                if (resolvedAncestor == null)
                {
                    // Defensive fallback: if resolution unexpectedly fails,
                    // return the original path unchanged
                    return fullPath;
                }

                // Append remaining non-existent segments
                var finalPath = resolvedAncestor;
                foreach (var segment in remainingSegments)
                {
                    finalPath = Path.Combine(finalPath, segment);
                }

                return finalPath;
            }

            var parent = Path.GetDirectoryName(currentPath);
            if (string.IsNullOrEmpty(parent))
            {
                // No existing ancestor found - return original path
                return fullPath;
            }

            var segmentName = Path.GetFileName(currentPath);
            if (!string.IsNullOrEmpty(segmentName))
            {
                // Prepend so segments remain in correct order
                remainingSegments.Insert(0, segmentName);
            }

            currentPath = parent;
        }
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

    /// <summary>
    /// Checks all path segments for reserved Windows device names.
    /// Reserved device names are invalid in ANY path component on Windows.
    /// </summary>
    /// <param name="canonicalPath">The canonical (full) path to check.</param>
    /// <param name="originalPath">The original path for error messages.</param>
    /// <remarks>
    /// Windows treats reserved device names as special in any path segment, and also
    /// with trailing dots/spaces (e.g., "CON.", "CON "). This method validates all
    /// segments and normalizes them before checking against the reserved list.
    /// 
    /// Examples of blocked paths:
    /// - C:\CON\file.txt (CON in path segment)
    /// - C:\safe\NUL\data.bin (NUL in path segment)
    /// - C:\path\COM1.txt (COM1 as filename)
    /// - C:\path\PRN. (PRN with trailing dot)
    /// </remarks>
    private static void CheckForReservedDeviceNames(string canonicalPath, string originalPath)
    {
        // Split path into segments
        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var segments = canonicalPath.Split(separators, StringSplitOptions.RemoveEmptyEntries);

        foreach (var segment in segments)
        {
            // Normalize segment: trim trailing dots and spaces (Windows treats these as equivalent)
            var normalizedSegment = segment.TrimEnd('.', ' ');
            
            if (string.IsNullOrEmpty(normalizedSegment))
            {
                continue;
            }

            // Check if the segment (without extension) is a reserved device name
            var nameWithoutExtension = Path.GetFileNameWithoutExtension(normalizedSegment);
            if (ReservedDeviceNames.Contains(nameWithoutExtension, StringComparer.OrdinalIgnoreCase))
            {
                throw new SecurityException($"Reserved device names are not permitted in any path segment: '{segment}' in path '{originalPath}'");
            }
        }
    }
}
