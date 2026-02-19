using System.Globalization;
using System.Security;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for creating or overwriting files with security validation and backup support.
/// Validates paths and creates backups before overwriting existing files.
/// Requires human approval before execution.
/// In v0.2.0, supports dynamic directory scoping via IAccessPolicyEngine.
/// </summary>
public class WriteFileTool : ToolBase
{
    private readonly string _defaultRoot;
    private readonly IFileOperations _fileOperations;
    private readonly IAccessPolicyEngine? _policyEngine;

    /// <summary>
    /// Initializes a new instance of the <see cref="WriteFileTool"/> class.
    /// </summary>
    /// <param name="defaultRoot">The default root directory (fallback when policy engine is null).</param>
    /// <param name="fileOperations">The file operations service.</param>
    /// <param name="policyEngine">The access policy engine for dynamic directory scoping (v0.2.0). If null, falls back to static root.</param>
    public WriteFileTool(string defaultRoot, IFileOperations fileOperations, IAccessPolicyEngine? policyEngine = null)
    {
        ArgumentNullException.ThrowIfNull(defaultRoot);
        ArgumentNullException.ThrowIfNull(fileOperations);
        _defaultRoot = defaultRoot;
        _fileOperations = fileOperations;
        _policyEngine = policyEngine;
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

            // Determine the directory to validate against
            string validatedPath;
            if (_policyEngine != null)
            {
                // v0.2.0: Dynamic directory scoping via policy engine
                // Extract directory from the path to request access
                var fileDirectory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? path;
                
                var request = new DirectoryAccessRequest(
                    Path: fileDirectory,
                    Level: AccessLevel.ReadWrite,
                    Justification: $"Writing file: {path}"
                );

                var decision = await _policyEngine.EvaluateAsync(request, cancellationToken).ConfigureAwait(false);

                if (decision.Outcome == AccessOutcome.Denied)
                {
                    var reasons = string.Join("; ", decision.DeniedReasons);
                    return $"Error: Access denied - {reasons}";
                }

                if (decision.Outcome == AccessOutcome.RequiresApproval)
                {
                    // Throw exception to trigger interactive approval flow in AgentOrchestrator
                    // Use canonical scoped path so orchestrator grant matches session store lookup
                    throw new DirectoryAccessRequiredException(decision.ScopedPath!, AccessLevel.ReadWrite, $"Writing file: {path}");
                }

                // Use the granted scoped path as the validation root
                validatedPath = _fileOperations.ValidatePath(path, decision.ScopedPath!);
            }
            else
            {
                // v0.1.x: Static root fallback (backward compatibility)
                validatedPath = _fileOperations.ValidatePath(path, _defaultRoot);
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
        catch (DirectoryAccessRequiredException)
        {
            // Must propagate to AgentOrchestrator for interactive approval flow
            throw;
        }
        catch (SecurityException ex)
        {
            return $"Error: Security validation failed - {ex.Message}";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error writing file - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
