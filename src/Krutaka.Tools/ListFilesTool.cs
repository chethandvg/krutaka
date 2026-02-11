using System.Security;
using System.Text;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for listing files matching a glob pattern with security validation.
/// Validates all paths and filters out blocked directories and patterns.
/// </summary>
public class ListFilesTool : ToolBase
{
    private readonly string _projectRoot;
    private readonly IFileOperations _fileOperations;

    /// <summary>
    /// Initializes a new instance of the <see cref="ListFilesTool"/> class.
    /// </summary>
    /// <param name="projectRoot">The allowed root directory for file access.</param>
    /// <param name="fileOperations">The file operations service.</param>
    public ListFilesTool(string projectRoot, IFileOperations fileOperations)
    {
        ArgumentNullException.ThrowIfNull(projectRoot);
        ArgumentNullException.ThrowIfNull(fileOperations);
        _projectRoot = projectRoot;
        _fileOperations = fileOperations;
    }

    /// <inheritdoc/>
    public override string Name => "list_files";

    /// <inheritdoc/>
    public override string Description => "Lists files in the project directory matching a search pattern. " +
        "Supports wildcards (* and ?) in the pattern. Searches recursively through all subdirectories. " +
        "Returns a newline-separated list of file paths relative to the project root. " +
        "Use this tool when you need to discover files by name or extension pattern.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("path", "string", "The directory path to search (relative to project root or absolute within project)", false),
        ("pattern", "string", "The search pattern (e.g., '*.cs', 'test*.txt'). Defaults to '*' (all files)", false)
    );

    /// <inheritdoc/>
    public override Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Check for cancellation
            cancellationToken.ThrowIfCancellationRequested();

            // Extract path parameter (default to project root)
            var path = _projectRoot;
            if (input.TryGetProperty("path", out var pathElement))
            {
                var providedPath = pathElement.GetString();
                if (!string.IsNullOrWhiteSpace(providedPath))
                {
                    path = providedPath;
                }
            }

            // Extract pattern parameter (default to all files)
            var pattern = "*";
            if (input.TryGetProperty("pattern", out var patternElement))
            {
                var providedPattern = patternElement.GetString();
                if (!string.IsNullOrWhiteSpace(providedPattern))
                {
                    pattern = providedPattern;
                }
            }

            // Validate path (security check)
            string validatedPath;
            try
            {
                validatedPath = _fileOperations.ValidatePath(path, _projectRoot);
            }
            catch (SecurityException ex)
            {
                return Task.FromResult($"Error: Security validation failed - {ex.Message}");
            }

            // Check if directory exists
            if (!Directory.Exists(validatedPath))
            {
                return Task.FromResult($"Error: Directory not found: '{path}'");
            }

            // Filter files through security validation and build result
            var result = new StringBuilder();
            var fileCount = 0;
            var blockedCount = 0;

            // Use EnumerationOptions to handle inaccessible directories gracefully
            var enumerationOptions = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true
            };

            try
            {
                foreach (var file in Directory.EnumerateFiles(validatedPath, pattern, enumerationOptions))
                {
                    // Check for cancellation periodically
                    cancellationToken.ThrowIfCancellationRequested();

                    // Validate each file path
                    try
                    {
                        _fileOperations.ValidatePath(file, _projectRoot);

                        // Make path relative to project root for cleaner output
                        var relativePath = Path.GetRelativePath(_projectRoot, file);
                        result.AppendLine(relativePath);
                        fileCount++;
                    }
                    catch (SecurityException)
                    {
                        // Silently skip blocked files (don't reveal their existence)
                        blockedCount++;
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                return Task.FromResult($"Error: Permission denied accessing directory: '{path}'");
            }
            catch (IOException ex)
            {
                return Task.FromResult($"Error: I/O error accessing directory: '{path}' - {ex.Message}");
            }

            if (fileCount == 0)
            {
                if (blockedCount > 0)
                {
                    return Task.FromResult($"No accessible files found matching pattern '{pattern}' in '{path}'. Some files were blocked by security policy.");
                }

                return Task.FromResult($"No files found matching pattern '{pattern}' in '{path}'.");
            }

            // Wrap output in untrusted_content tags for prompt injection defense
            var listPayload = result.ToString().TrimEnd();
            var wrappedPayload = $"<untrusted_content>\n{listPayload}\n</untrusted_content>";
            return Task.FromResult(wrappedPayload);
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return Task.FromResult($"Error: Unexpected error listing files - {ex.Message}");
        }
#pragma warning restore CA1031
    }
}
