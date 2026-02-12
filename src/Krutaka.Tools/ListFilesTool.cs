using System.Security;
using System.Text;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for listing files matching a glob pattern with security validation.
/// Validates all paths and filters out blocked directories and patterns.
/// In v0.2.0, supports dynamic directory scoping via IAccessPolicyEngine.
/// </summary>
public class ListFilesTool : ToolBase
{
    private readonly string _defaultRoot;
    private readonly IFileOperations _fileOperations;
    private readonly IAccessPolicyEngine? _policyEngine;

    /// <summary>
    /// Initializes a new instance of the <see cref="ListFilesTool"/> class.
    /// </summary>
    /// <param name="defaultRoot">The default root directory (fallback when policy engine is null).</param>
    /// <param name="fileOperations">The file operations service.</param>
    /// <param name="policyEngine">The access policy engine for dynamic directory scoping (v0.2.0). If null, falls back to static root.</param>
    public ListFilesTool(string defaultRoot, IFileOperations fileOperations, IAccessPolicyEngine? policyEngine = null)
    {
        ArgumentNullException.ThrowIfNull(defaultRoot);
        ArgumentNullException.ThrowIfNull(fileOperations);
        _defaultRoot = defaultRoot;
        _fileOperations = fileOperations;
        _policyEngine = policyEngine;
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
    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Check for cancellation
            cancellationToken.ThrowIfCancellationRequested();

            // Extract path parameter (default to default root)
            var path = _defaultRoot;
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

            // Determine the directory to validate against
            string validatedPath;
            string projectRoot;
            if (_policyEngine != null)
            {
                // v0.2.0: Dynamic directory scoping via policy engine
                var request = new DirectoryAccessRequest(
                    Path: path,
                    Level: AccessLevel.ReadOnly,
                    Justification: $"Listing files in: {path}"
                );

                var decision = await _policyEngine.EvaluateAsync(request, cancellationToken).ConfigureAwait(false);

                if (decision.Outcome == AccessOutcome.Denied)
                {
                    var reasons = string.Join("; ", decision.DeniedReasons);
                    return $"Error: Access denied - {reasons}";
                }

                if (decision.Outcome == AccessOutcome.RequiresApproval)
                {
                    return $"Error: Access to directory '{path}' requires approval. This functionality will be available in v0.2.0-9.";
                }

                // Use the granted scoped path as the validation root
                validatedPath = _fileOperations.ValidatePath(path, decision.ScopedPath!);
                projectRoot = decision.ScopedPath!;
            }
            else
            {
                // v0.1.x: Static root fallback (backward compatibility)
                validatedPath = _fileOperations.ValidatePath(path, _defaultRoot);
                projectRoot = _defaultRoot;
            }

            // Check if directory exists
            if (!Directory.Exists(validatedPath))
            {
                return $"Error: Directory not found: '{path}'";
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
                        _fileOperations.ValidatePath(file, projectRoot);

                        // Make path relative to project root for cleaner output
                        var relativePath = Path.GetRelativePath(projectRoot, file);
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
                return $"Error: Permission denied accessing directory: '{path}'";
            }
            catch (IOException ex)
            {
                return $"Error: I/O error accessing directory: '{path}' - {ex.Message}";
            }

            if (fileCount == 0)
            {
                if (blockedCount > 0)
                {
                    return $"No accessible files found matching pattern '{pattern}' in '{path}'. Some files were blocked by security policy.";
                }

                return $"No files found matching pattern '{pattern}' in '{path}'.";
            }

            // Wrap output in untrusted_content tags for prompt injection defense
            var listPayload = result.ToString().TrimEnd();
            var wrappedPayload = $"<untrusted_content>\n{listPayload}\n</untrusted_content>";
            return wrappedPayload;
        }
        catch (SecurityException ex)
        {
            return $"Error: Security validation failed - {ex.Message}";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error listing files - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
