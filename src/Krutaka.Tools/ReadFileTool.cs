using System.Security;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for reading file contents with security validation.
/// Validates paths and enforces 1MB size limit before reading.
/// </summary>
public class ReadFileTool : ToolBase
{
    private readonly string _projectRoot;
    private readonly IFileOperations _fileOperations;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReadFileTool"/> class.
    /// </summary>
    /// <param name="projectRoot">The allowed root directory for file access.</param>
    /// <param name="fileOperations">The file operations service for security validation.</param>
    public ReadFileTool(string projectRoot, IFileOperations fileOperations)
    {
        ArgumentNullException.ThrowIfNull(projectRoot);
        ArgumentNullException.ThrowIfNull(fileOperations);
        _projectRoot = projectRoot;
        _fileOperations = fileOperations;
    }

    /// <inheritdoc/>
    public override string Name => "read_file";

    /// <inheritdoc/>
    public override string Description => "Reads the contents of a text file from the project directory. " +
        "The file must exist within the project root and be under 1MB in size. " +
        "Returns the complete file contents. " +
        "Use this tool when you need to examine source code, configuration files, or documentation.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("path", "string", "The file path to read (relative to project root or absolute within project)", true)
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

            // Validate path (security check)
            string validatedPath;
            try
            {
                validatedPath = _fileOperations.ValidatePath(path, _projectRoot);
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
                _fileOperations.ValidateFileSize(validatedPath);
            }
            catch (SecurityException ex)
            {
                return $"Error: File size validation failed - {ex.Message}";
            }

            // Read file content
            string content;
            try
            {
                content = await File.ReadAllTextAsync(validatedPath, cancellationToken).ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException)
            {
                return $"Error: Permission denied reading file: '{path}'";
            }
            catch (IOException ex)
            {
                return $"Error: I/O error reading file: '{path}' - {ex.Message}";
            }

            // Wrap content in untrusted_content tags to prevent prompt injection
            return $"<untrusted_content>\n{content}\n</untrusted_content>";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error reading file - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
