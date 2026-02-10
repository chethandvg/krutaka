using System.Globalization;
using System.Security;
using System.Text;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for editing files by replacing content in a specific line range.
/// Validates paths, creates backups, and returns a diff of changes.
/// Requires human approval before execution.
/// </summary>
public class EditFileTool : ToolBase
{
    private readonly string _projectRoot;

    /// <summary>
    /// Initializes a new instance of the <see cref="EditFileTool"/> class.
    /// </summary>
    /// <param name="projectRoot">The allowed root directory for file access.</param>
    public EditFileTool(string projectRoot)
    {
        ArgumentNullException.ThrowIfNull(projectRoot);
        _projectRoot = projectRoot;
    }

    /// <inheritdoc/>
    public override string Name => "edit_file";

    /// <inheritdoc/>
    public override string Description => "Edits an existing file by replacing content in a specific line range. " +
        "Line numbers are 1-indexed (first line is 1). " +
        "The file must exist within the project root. " +
        "A backup copy is created before editing. " +
        "Returns a diff showing the changes made. " +
        "This is a destructive operation that requires human approval.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("path", "string", "The file path to edit (relative to project root or absolute within project)", true),
        ("content", "string", "The new content to replace the specified line range", true),
        ("start_line", "number", "The starting line number (1-indexed, inclusive)", true),
        ("end_line", "number", "The ending line number (1-indexed, inclusive)", true)
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

            // Extract start_line parameter
            if (!input.TryGetProperty("start_line", out var startLineElement))
            {
                return "Error: Missing required parameter 'start_line'";
            }

            if (!startLineElement.TryGetInt32(out var startLine))
            {
                return "Error: Parameter 'start_line' must be a valid integer";
            }

            // Extract end_line parameter
            if (!input.TryGetProperty("end_line", out var endLineElement))
            {
                return "Error: Missing required parameter 'end_line'";
            }

            if (!endLineElement.TryGetInt32(out var endLine))
            {
                return "Error: Parameter 'end_line' must be a valid integer";
            }

            // Validate line numbers
            if (startLine < 1)
            {
                return "Error: start_line must be >= 1 (1-indexed)";
            }

            if (endLine < startLine)
            {
                return "Error: end_line must be >= start_line";
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

            // Check if file exists
            if (!File.Exists(validatedPath))
            {
                return $"Error: File not found: '{path}'";
            }

            // Validate file size (security check)
            try
            {
                SafeFileOperations.ValidateFileSize(validatedPath);
            }
            catch (SecurityException ex)
            {
                return $"Error: File size validation failed - {ex.Message}";
            }

            // Read existing file content
            string[] lines;
            try
            {
                var fileContent = await File.ReadAllTextAsync(validatedPath, cancellationToken).ConfigureAwait(false);
                lines = fileContent.Split('\n');
            }
            catch (UnauthorizedAccessException)
            {
                return $"Error: Permission denied reading file: '{path}'";
            }
            catch (IOException ex)
            {
                return $"Error: I/O error reading file: '{path}' - {ex.Message}";
            }

            // Validate line range against file size
            if (startLine > lines.Length)
            {
                return $"Error: start_line ({startLine}) exceeds file length ({lines.Length} lines)";
            }

            if (endLine > lines.Length)
            {
                return $"Error: end_line ({endLine}) exceeds file length ({lines.Length} lines)";
            }

            // Create backup before editing
            try
            {
                _ = CreateBackup(validatedPath);
            }
#pragma warning disable CA1031 // Do not catch general exception types - backup failure should not prevent edit
            catch (Exception ex)
#pragma warning restore CA1031
            {
                return $"Error: Failed to create backup - {ex.Message}";
            }

            // Preserve original line endings
            var originalContent = string.Join('\n', lines);

            // Build new file content with replaced line range
            var newLines = new List<string>();
            
            // Add lines before the edit range (0-indexed, so start_line - 1)
            for (var i = 0; i < startLine - 1 && i < lines.Length; i++)
            {
                newLines.Add(lines[i]);
            }

            // Add new content
            newLines.Add(content);

            // Add lines after the edit range (0-indexed, so endLine is inclusive)
            for (var i = endLine; i < lines.Length; i++)
            {
                newLines.Add(lines[i]);
            }

            var newContent = string.Join('\n', newLines);

            // Write updated content
            try
            {
                await File.WriteAllTextAsync(validatedPath, newContent, cancellationToken).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                return $"Error: Permission denied writing file: '{path}'";
            }
            catch (IOException ex)
            {
                return $"Error: I/O error writing file: '{path}' - {ex.Message}";
            }

            // Generate diff
            var diff = GenerateDiff(lines, newLines.ToArray(), startLine, endLine);

            return $"Successfully edited file: '{path}'\n\nDiff:\n{diff}";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error editing file - {ex.Message}";
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Creates a backup copy of the specified file in a temporary directory.
    /// </summary>
    /// <param name="filePath">The file to backup.</param>
    /// <returns>The path to the backup file.</returns>
    private static string CreateBackup(string filePath)
    {
        ArgumentNullException.ThrowIfNull(filePath);

        var fileName = Path.GetFileName(filePath);
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var backupFileName = $"{fileName}.{timestamp}.bak";
        var backupPath = Path.Combine(Path.GetTempPath(), "krutaka-backups", backupFileName);

        var backupDir = Path.GetDirectoryName(backupPath);
        if (!string.IsNullOrEmpty(backupDir))
        {
            Directory.CreateDirectory(backupDir);
        }

        File.Copy(filePath, backupPath, overwrite: true);
        return backupPath;
    }

    /// <summary>
    /// Generates a unified diff showing the changes made to the file.
    /// </summary>
    /// <param name="oldLines">Original file lines.</param>
    /// <param name="newLines">Modified file lines.</param>
    /// <param name="startLine">Starting line of the edit (1-indexed).</param>
    /// <param name="endLine">Ending line of the edit (1-indexed).</param>
    /// <returns>A diff string showing the changes.</returns>
    private static string GenerateDiff(string[] oldLines, string[] newLines, int startLine, int endLine)
    {
        var diff = new StringBuilder();
        diff.AppendLine(CultureInfo.InvariantCulture, $"@@ -{startLine},{endLine - startLine + 1} +{startLine},{newLines.Length - oldLines.Length + (endLine - startLine + 1)} @@");

        // Show removed lines
        for (var i = startLine - 1; i < endLine && i < oldLines.Length; i++)
        {
            diff.AppendLine(CultureInfo.InvariantCulture, $"- {oldLines[i]}");
        }

        // Show added lines (the new content in the range)
        // Find the new content lines (between startLine-1 and the replacement)
        if (newLines.Length >= startLine)
        {
            var replacementLine = newLines[startLine - 1];
            diff.AppendLine(CultureInfo.InvariantCulture, $"+ {replacementLine}");
        }

        return diff.ToString();
    }
}
