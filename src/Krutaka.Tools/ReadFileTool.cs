using System.Security;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for reading file contents with security validation.
/// Validates paths and enforces 1MB size limit before reading.
/// In v0.2.0, supports dynamic directory scoping via IAccessPolicyEngine.
/// </summary>
public class ReadFileTool : ToolBase
{
    private readonly string _defaultRoot;
    private readonly IFileOperations _fileOperations;
    private readonly IAccessPolicyEngine? _policyEngine;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReadFileTool"/> class.
    /// </summary>
    /// <param name="defaultRoot">The default root directory (fallback when policy engine is null).</param>
    /// <param name="fileOperations">The file operations service for security validation.</param>
    /// <param name="policyEngine">The access policy engine for dynamic directory scoping (v0.2.0). If null, falls back to static root.</param>
    public ReadFileTool(string defaultRoot, IFileOperations fileOperations, IAccessPolicyEngine? policyEngine = null)
    {
        ArgumentNullException.ThrowIfNull(defaultRoot);
        ArgumentNullException.ThrowIfNull(fileOperations);
        _defaultRoot = defaultRoot;
        _fileOperations = fileOperations;
        _policyEngine = policyEngine;
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

            // Determine the directory to validate against
            string validatedPath;
            if (_policyEngine != null)
            {
                // v0.2.0: Dynamic directory scoping via policy engine
                // Extract directory from the path to request access
                var fileDirectory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? path;
                
                var request = new DirectoryAccessRequest(
                    Path: fileDirectory,
                    Level: AccessLevel.ReadOnly,
                    Justification: $"Reading file: {path}"
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
                    throw new DirectoryAccessRequiredException(decision.ScopedPath!, AccessLevel.ReadOnly, $"Reading file: {path}");
                }

                // Use the granted scoped path as the validation root
                validatedPath = _fileOperations.ValidatePath(path, decision.ScopedPath!);
            }
            else
            {
                // v0.1.x: Static root fallback (backward compatibility)
                validatedPath = _fileOperations.ValidatePath(path, _defaultRoot);
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
        catch (SecurityException ex)
        {
            return $"Error: Security validation failed - {ex.Message}";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error reading file - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
