using System.Security;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Types;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

/// <summary>
/// Handles file upload (receive) and download (send) operations through Telegram
/// with comprehensive security validation.
/// </summary>
public sealed class TelegramFileHandler : ITelegramFileHandler
{
    private readonly ITelegramBotClient _botClient;
    private readonly IAccessPolicyEngine _accessPolicyEngine;
    private readonly ILogger<TelegramFileHandler>? _logger;

    // Temp directory name within project path
    private const string TempDirectoryName = ".krutaka-temp";

    // File size limits
    private const long MaxReceiveFileSizeBytes = 10 * 1024 * 1024; // 10MB
    private const long MaxSendFileSizeBytes = 50 * 1024 * 1024; // 50MB (Telegram limit)

    // Allowed file extensions (case-insensitive)
    private static readonly HashSet<string> AllowedExtensions =
    [
        ".cs", ".json", ".xml", ".md", ".txt", ".yaml", ".yml",
        ".py", ".js", ".ts", ".html", ".css",
        ".csproj", ".sln", ".slnx", ".props", ".config",
        ".sh", ".bat", ".log", ".csv", ".sql"
    ];

    // Blocked executable extensions (case-insensitive)
    private static readonly HashSet<string> BlockedExecutableExtensions =
    [
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".msi",
        ".vbs", ".scr", ".com", ".pif", ".reg", ".wsf", ".hta"
    ];

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramFileHandler"/> class.
    /// </summary>
    /// <param name="botClient">The Telegram bot client for file operations.</param>
    /// <param name="accessPolicyEngine">The access policy engine for path validation.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    public TelegramFileHandler(
        ITelegramBotClient botClient,
        IAccessPolicyEngine accessPolicyEngine,
        ILogger<TelegramFileHandler>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(botClient);
        ArgumentNullException.ThrowIfNull(accessPolicyEngine);

        _botClient = botClient;
        _accessPolicyEngine = accessPolicyEngine;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<FileReceiveResult> ReceiveFileAsync(
        Message message,
        ManagedSession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(session);

        // Extract document info
        var document = message.Document;
        if (document is null)
        {
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: null,
                FileSize: 0,
                Error: "No document found in message");
        }

        var fileName = document.FileName ?? $"document_{document.FileId}";
        var fileSize = document.FileSize ?? 0;

        // Validate file size
        if (fileSize > MaxReceiveFileSizeBytes)
        {
            _logger?.LogWarning(
                "File upload rejected: size {FileSize} exceeds {MaxSize} bytes. File: {FileName}",
                fileSize, MaxReceiveFileSizeBytes, fileName);
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"File size {fileSize} bytes exceeds maximum {MaxReceiveFileSizeBytes} bytes (10MB)");
        }

        // Validate filename for path traversal
        if (ContainsPathTraversal(fileName))
        {
            _logger?.LogWarning(
                "File upload rejected: path traversal detected in filename: {FileName}",
                fileName);
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"Filename contains invalid path traversal characters: {fileName}");
        }

        // Validate filename for reserved device names
        if (IsReservedDeviceName(fileName))
        {
            _logger?.LogWarning(
                "File upload rejected: reserved device name detected in filename: {FileName}",
                fileName);
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"Filename contains reserved device name: {fileName}");
        }

        // Validate file extension (check for double-extension bypass)
        var extensionError = ValidateFileExtension(fileName);
        if (extensionError is not null)
        {
            _logger?.LogWarning(
                "File upload rejected: {Error}. File: {FileName}",
                extensionError, fileName);
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: extensionError);
        }

        // Create temp directory if it doesn't exist
        var tempDir = Path.Combine(session.ProjectPath, TempDirectoryName);
        try
        {
            Directory.CreateDirectory(tempDir);
        }
#pragma warning disable CA1031 // Do not catch general exception types - directory creation failures must be reported as file receive errors
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger?.LogError(ex, "Failed to create temp directory: {TempDir}", tempDir);
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"Failed to create temp directory: {ex.Message}");
        }

        // Build target path
        var targetPath = Path.Combine(tempDir, fileName);

        // Resolve and validate the path through PathResolver and AccessPolicyEngine
        string resolvedPath;
        try
        {
            resolvedPath = PathResolver.ResolveToFinalTarget(targetPath);
        }
        catch (SecurityException ex)
        {
            _logger?.LogWarning(
                ex,
                "File upload rejected: path resolution failed for {TargetPath}",
                targetPath);
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"Path validation failed: {ex.Message}");
        }

        // Validate through access policy engine
        var accessRequest = new DirectoryAccessRequest(
            Path: tempDir,
            Level: AccessLevel.ReadWrite,
            Justification: $"File upload: {fileName}");

        var accessDecision = await _accessPolicyEngine.EvaluateAsync(accessRequest, cancellationToken).ConfigureAwait(false);
        if (accessDecision.Outcome != AccessOutcome.Granted)
        {
            _logger?.LogWarning(
                "File upload rejected: access policy denied for {TempDir}. Reasons: {Reasons}",
                tempDir, string.Join(", ", accessDecision.DeniedReasons));
            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"Access policy denied: {string.Join(", ", accessDecision.DeniedReasons)}");
        }

        // Download the file
        try
        {
            var fileInfo = await _botClient.GetFile(document.FileId, cancellationToken).ConfigureAwait(false);
            if (fileInfo.FilePath is null)
            {
                return new FileReceiveResult(
                    Success: false,
                    LocalPath: null,
                    FileName: fileName,
                    FileSize: fileSize,
                    Error: "Telegram file path is null");
            }

            using var fileStream = System.IO.File.Create(targetPath);
            await _botClient.DownloadFile(fileInfo.FilePath, fileStream, cancellationToken).ConfigureAwait(false);

            _logger?.LogInformation(
                "File uploaded successfully: {FileName} ({FileSize} bytes) to {TargetPath}",
                fileName, fileSize, targetPath);

            return new FileReceiveResult(
                Success: true,
                LocalPath: resolvedPath,
                FileName: fileName,
                FileSize: fileSize,
                Error: null);
        }
#pragma warning disable CA1031 // Do not catch general exception types - file handler must never crash and always return structured result
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _logger?.LogError(ex, "Failed to download file: {FileName}", fileName);
            
            // Clean up partial file if it exists
            try
            {
                if (System.IO.File.Exists(targetPath))
                {
                    System.IO.File.Delete(targetPath);
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types - cleanup failures should not propagate
            catch
#pragma warning restore CA1031
            {
                // Ignore cleanup errors
            }

            return new FileReceiveResult(
                Success: false,
                LocalPath: null,
                FileName: fileName,
                FileSize: fileSize,
                Error: $"Failed to download file: {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public async Task SendFileAsync(
        long chatId,
        string filePath,
        string? caption,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        // Check if file exists
        if (!System.IO.File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}", filePath);
        }

        // Get file info and validate size
        var fileInfo = new FileInfo(filePath);
        if (fileInfo.Length > MaxSendFileSizeBytes)
        {
            throw new ArgumentException(
                $"File size {fileInfo.Length} bytes exceeds Telegram's 50MB limit",
                nameof(filePath));
        }

        // Sanitize caption if provided
        string? sanitizedCaption = null;
        if (!string.IsNullOrWhiteSpace(caption))
        {
            // Extract user ID from chatId for source attribution
            // In this context, chatId is the destination, so we use it as the source ID
            sanitizedCaption = TelegramInputSanitizer.SanitizeFileCaption(caption, chatId);
        }

        // Send the file
        using var stream = System.IO.File.OpenRead(filePath);
        var inputFile = InputFile.FromStream(stream, fileInfo.Name);

        await _botClient.SendDocument(
            chatId: chatId,
            document: inputFile,
            caption: sanitizedCaption,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        _logger?.LogInformation(
            "File sent to chat {ChatId}: {FilePath} ({FileSize} bytes)",
            chatId, filePath, fileInfo.Length);
    }

    /// <summary>
    /// Validates the file extension against allowlist and blocklist.
    /// Checks for double-extension bypass attacks (e.g., file.txt.exe).
    /// </summary>
    /// <param name="fileName">The filename to validate.</param>
    /// <returns>An error message if validation fails; otherwise, null.</returns>
    private static string? ValidateFileExtension(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return "Filename is empty";
        }

        // Get all extensions (to detect double-extension)
        var extensions = GetAllExtensions(fileName);
        if (extensions.Count == 0)
        {
            return "Filename has no extension";
        }

        // Check if ANY extension is a blocked executable
        foreach (var ext in extensions)
        {
            if (BlockedExecutableExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
            {
                return $"Executable extension '{ext}' is not permitted";
            }
        }

        // Check if the FINAL extension is in the allowlist
        var finalExtension = extensions[^1];
        if (!AllowedExtensions.Contains(finalExtension, StringComparer.OrdinalIgnoreCase))
        {
            return $"File extension '{finalExtension}' is not in the allowlist";
        }

        return null;
    }

    /// <summary>
    /// Gets all extensions from a filename (to detect double-extension bypass).
    /// Example: "file.txt.exe" → [".txt", ".exe"]
    /// </summary>
    private static List<string> GetAllExtensions(string fileName)
    {
        var extensions = new List<string>();
        var name = fileName;

        while (true)
        {
            var ext = Path.GetExtension(name);
            if (string.IsNullOrEmpty(ext))
            {
                break;
            }

            extensions.Insert(0, ext); // Prepend to maintain order
            name = Path.GetFileNameWithoutExtension(name);
        }

        return extensions;
    }

    /// <summary>
    /// Checks if a filename contains path traversal characters.
    /// Rejects filenames containing "..", "/", "\", or any path separator.
    /// </summary>
    private static bool ContainsPathTraversal(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return true;
        }

        // Check for ".." (parent directory traversal)
        if (fileName.Contains("..", StringComparison.Ordinal))
        {
            return true;
        }

        // Check for any path separators
#pragma warning disable CA1307 // char.Contains does not have a StringComparison overload in .NET 10
        if (fileName.Contains('/') || fileName.Contains('\\'))
        {
            return true;
        }

        if (fileName.Contains(Path.DirectorySeparatorChar) ||
            fileName.Contains(Path.AltDirectorySeparatorChar))
        {
            return true;
        }
#pragma warning restore CA1307

        return false;
    }

    /// <summary>
    /// Checks if a filename is a reserved Windows device name.
    /// Reuses the logic from PathResolver for consistency.
    /// </summary>
    private static bool IsReservedDeviceName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return false;
        }

        // Normalize: trim trailing dots and spaces (Windows treats these as equivalent)
        var normalized = fileName.TrimEnd('.', ' ');
        if (string.IsNullOrEmpty(normalized))
        {
            return false;
        }

        // Get the name without extension
        var nameWithoutExtension = Path.GetFileNameWithoutExtension(normalized);

        // Reserved device names (same as PathResolver)
        var reservedNames = new[]
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
        };

        return reservedNames.Contains(nameWithoutExtension, StringComparer.OrdinalIgnoreCase);
    }
}
