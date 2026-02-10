using System.Globalization;
using System.Security;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for creating or overwriting files with security validation and backup support.
/// Validates paths and creates backups before overwriting existing files.
/// Requires human approval before execution.
/// </summary>
public class WriteFileTool : ToolBase
{
    private readonly string _projectRoot;

    /// <summary>
    /// Initializes a new instance of the <see cref="WriteFileTool"/> class.
    /// </summary>
    /// <param name="projectRoot">The allowed root directory for file access.</param>
    public WriteFileTool(string projectRoot)
    {
        ArgumentNullException.ThrowIfNull(projectRoot);
        _projectRoot = projectRoot;
    }

    /// <inheritdoc/>
    public override string Name => "write_file";

    /// <inheritdoc/>
    public override string Description => "Creates a new file or overwrites an existing file with the provided content. " +
        "The file path must be within the project root. " +
        "If the file already exists, a backup copy is created before overwriting. " +
        "Parent directories are created automatically if they don't exist. " +
        "This is a destructive operation that requires human approval.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("path", "string", "The file path to write (relative to project root or absolute within project)", true),
        ("content", "string", "The content to write to the file", true)
    );

    /// <inheritdoc/>
    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Extract path parameter
            if (!input.TryGetProperty("path", out var pathElement))
            {
                return "Error: Missing required parameter 'path'";
            }

            var path = pathElement.GetString();
            if (string.IsNullOrWhiteSpace(path))
            {
                return "Error: Parameter 'path' cannot be empty";
            }

            // Extract content parameter
            if (!input.TryGetProperty("content", out var contentElement))
            {
                return "Error: Missing required parameter 'content'";
            }

            var content = contentElement.GetString();
            if (content is null)
            {
                return "Error: Parameter 'content' cannot be null";
            }

            // Validate path (security check)
            string validatedPath;
            try
            {
                validatedPath = SafeFileOperations.ValidatePath(path, _projectRoot);
            }
            catch (SecurityException ex)
            {
                return $"Error: Security validation failed - {ex.Message}";
            }

            // Create parent directory if it doesn't exist
            var directory = Path.GetDirectoryName(validatedPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                try
                {
                    Directory.CreateDirectory(directory);
                }
                catch (UnauthorizedAccessException)
                {
                    return $"Error: Permission denied creating directory: '{directory}'";
                }
                catch (IOException ex)
                {
                    return $"Error: I/O error creating directory: '{directory}' - {ex.Message}";
                }
            }

            // Create backup if file exists
            if (File.Exists(validatedPath))
            {
                try
                {
                    _ = BackupHelper.CreateBackup(validatedPath);
                    // Note: Backup path is logged but not returned to prevent temp directory disclosure
                }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    return $"Error: Failed to create backup - {ex.Message}";
                }
            }

            // Write content to file
            try
            {
                await File.WriteAllTextAsync(validatedPath, content, cancellationToken).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                return $"Error: Permission denied writing file: '{path}'";
            }
            catch (IOException ex)
            {
                return $"Error: I/O error writing file: '{path}' - {ex.Message}";
            }

            return $"Successfully wrote file: '{path}' ({content.Length} characters)";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error writing file - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
