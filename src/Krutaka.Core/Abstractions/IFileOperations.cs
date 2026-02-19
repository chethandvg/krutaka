using System.Security;

namespace Krutaka.Core;

/// <summary>
/// Service for secure file path validation and operations.
/// Prevents path traversal, blocks access to sensitive directories and files.
/// </summary>
public interface IFileOperations
{
    /// <summary>
    /// Maximum file size allowed for read operations (1 MB).
    /// </summary>
    long MaxFileSizeBytes { get; }

    /// <summary>
    /// Validates a file path for read or write access.
    /// Performs canonicalization and checks against blocked directories and patterns.
    /// Logs security violations if audit logger is configured.
    /// </summary>
    /// <param name="path">The path to validate (can be relative or absolute).</param>
    /// <param name="allowedRoot">The allowed root directory (project root).</param>
    /// <param name="correlationContext">Optional correlation context for audit logging.</param>
    /// <returns>The canonicalized, validated absolute path.</returns>
    /// <exception cref="SecurityException">Thrown if the path violates security policy.</exception>
    string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null);

    /// <summary>
    /// Validates that a file size does not exceed the maximum allowed size.
    /// Logs security violations if audit logger is configured.
    /// </summary>
    /// <param name="filePath">The file path to check.</param>
    /// <param name="correlationContext">Optional correlation context for audit logging.</param>
    /// <exception cref="SecurityException">Thrown if the file exceeds the size limit.</exception>
    void ValidateFileSize(string filePath, CorrelationContext? correlationContext = null);
}
