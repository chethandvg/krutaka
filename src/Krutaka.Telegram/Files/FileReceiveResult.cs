namespace Krutaka.Telegram;

/// <summary>
/// Result of a file receive operation from Telegram.
/// Contains the outcome, local path, metadata, and error details.
/// </summary>
/// <param name="Success">True if the file was successfully downloaded and validated; otherwise, false.</param>
/// <param name="LocalPath">The absolute local file path where the file was saved (null if failed).</param>
/// <param name="FileName">The original filename from Telegram (null if not available).</param>
/// <param name="FileSize">The file size in bytes (0 if failed).</param>
/// <param name="Error">The error message if the operation failed (null if successful).</param>
public record FileReceiveResult(
    bool Success,
    string? LocalPath,
    string? FileName,
    long FileSize,
    string? Error);
