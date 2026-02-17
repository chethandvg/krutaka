using Krutaka.Core;
using Telegram.Bot.Types;

namespace Krutaka.Telegram;

/// <summary>
/// Handles file upload (receive) and download (send) operations through Telegram
/// with comprehensive security validation.
/// </summary>
public interface ITelegramFileHandler
{
    /// <summary>
    /// Downloads and validates a file uploaded to Telegram.
    /// Performs extension validation, size checks, path traversal detection,
    /// and device name validation before placing the file in a per-session temp directory.
    /// </summary>
    /// <param name="message">The Telegram message containing the file document.</param>
    /// <param name="session">The managed session for correlation and path scoping.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A FileReceiveResult indicating success or failure with error details.</returns>
    /// <remarks>
    /// Files are downloaded to {session.ProjectPath}/.krutaka-temp/{filename}.
    /// The temp directory is automatically registered for cleanup when the session is disposed.
    /// </remarks>
    Task<FileReceiveResult> ReceiveFileAsync(
        Message message,
        ManagedSession session,
        CancellationToken cancellationToken);

    /// <summary>
    /// Sends a file from the local filesystem to a Telegram chat.
    /// Validates the file exists, is within accessible paths, and meets size limits.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID to send the file to.</param>
    /// <param name="filePath">The absolute local file path to send.</param>
    /// <param name="session">The managed session for access policy validation.</param>
    /// <param name="caption">Optional caption to include with the file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the async operation.</returns>
    /// <exception cref="FileNotFoundException">Thrown if the file does not exist.</exception>
    /// <exception cref="UnauthorizedAccessException">Thrown if the file is outside accessible paths.</exception>
    /// <exception cref="ArgumentException">Thrown if the file exceeds Telegram's 50MB limit.</exception>
    Task SendFileAsync(
        long chatId,
        string filePath,
        ManagedSession session,
        string? caption,
        CancellationToken cancellationToken);
}
