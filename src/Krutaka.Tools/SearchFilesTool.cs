using System.Globalization;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Tool for searching file contents using text or regex patterns with security validation.
/// Provides grep-like functionality with file path and line number reporting.
/// </summary>
public class SearchFilesTool : ToolBase
{
    private readonly string _projectRoot;
    private readonly IFileOperations _fileOperations;

    /// <summary>
    /// Initializes a new instance of the <see cref="SearchFilesTool"/> class.
    /// </summary>
    /// <param name="projectRoot">The allowed root directory for file access.</param>
    /// <param name="fileOperations">The file operations service.</param>
    public SearchFilesTool(string projectRoot, IFileOperations fileOperations)
    {
        ArgumentNullException.ThrowIfNull(projectRoot);
        ArgumentNullException.ThrowIfNull(fileOperations);
        _projectRoot = projectRoot;
        _fileOperations = fileOperations;
    }

    /// <inheritdoc/>
    public override string Name => "search_files";

    /// <inheritdoc/>
    public override string Description => "Searches for text or regex patterns in files within the project directory. " +
        "Searches recursively through all text files, respecting the 1MB file size limit. " +
        "Returns matching lines with file path and line number. " +
        "Use this tool when you need to find specific code patterns, function calls, or text across multiple files.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("pattern", "string", "The text or regex pattern to search for", true),
        ("path", "string", "The directory path to search (relative to project root or absolute within project). Defaults to project root", false),
        ("file_pattern", "string", "File name pattern to search in (e.g., '*.cs', '*.txt'). Defaults to '*' (all files)", false),
        ("regex", "boolean", "Whether to treat the pattern as a regex. Defaults to false (plain text search)", false),
        ("case_sensitive", "boolean", "Whether the search is case-sensitive. Defaults to false", false)
    );

    /// <inheritdoc/>
    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Extract pattern parameter (required)
            if (!input.TryGetProperty("pattern", out var patternElement))
            {
                return "Error: Missing required parameter 'pattern'";
            }

            var searchPattern = patternElement.GetString();
            if (string.IsNullOrWhiteSpace(searchPattern))
            {
                return "Error: Parameter 'pattern' cannot be empty";
            }

            // Extract optional parameters
            var path = _projectRoot;
            if (input.TryGetProperty("path", out var pathElement))
            {
                var providedPath = pathElement.GetString();
                if (!string.IsNullOrWhiteSpace(providedPath))
                {
                    path = providedPath;
                }
            }

            var filePattern = "*";
            if (input.TryGetProperty("file_pattern", out var filePatternElement))
            {
                var providedFilePattern = filePatternElement.GetString();
                if (!string.IsNullOrWhiteSpace(providedFilePattern))
                {
                    filePattern = providedFilePattern;
                }
            }

            var useRegex = false;
            if (input.TryGetProperty("regex", out var regexElement))
            {
                useRegex = regexElement.GetBoolean();
            }

            var caseSensitive = false;
            if (input.TryGetProperty("case_sensitive", out var caseSensitiveElement))
            {
                caseSensitive = caseSensitiveElement.GetBoolean();
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

            // Check if directory exists
            if (!Directory.Exists(validatedPath))
            {
                return $"Error: Directory not found: '{path}'";
            }

            // Compile regex if needed (without Compiled option for user-supplied patterns)
            Regex? regex = null;
            if (useRegex)
            {
                try
                {
                    var options = caseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase;
                    regex = new Regex(searchPattern, options, TimeSpan.FromSeconds(1));
                }
                catch (ArgumentException ex)
                {
                    return $"Error: Invalid regex pattern - {ex.Message}";
                }
            }

            // Search files and collect matches
            var result = new StringBuilder();
            var matchCount = 0;
            var fileCount = 0;
            var stringComparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

            // Use EnumerationOptions to handle inaccessible directories gracefully
            var enumerationOptions = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true
            };

            try
            {
                foreach (var file in Directory.EnumerateFiles(validatedPath, filePattern, enumerationOptions))
                {
                    // Check for cancellation periodically
                    cancellationToken.ThrowIfCancellationRequested();

                    // Validate file path
                    try
                    {
                        _fileOperations.ValidatePath(file, _projectRoot);
                    }
                    catch (SecurityException)
                    {
                        // Silently skip blocked files
                        continue;
                    }

                    // Validate file size
                    try
                    {
                        _fileOperations.ValidateFileSize(file);
                    }
                    catch (SecurityException)
                    {
                        // Silently skip files that are too large
                        continue;
                    }

                    // Search file content
                    try
                    {
                        var relativePath = Path.GetRelativePath(_projectRoot, file);
                        var lineNumber = 0;
                        var fileHasMatches = false;

                        await foreach (var line in File.ReadLinesAsync(file, cancellationToken).ConfigureAwait(false))
                        {
                            lineNumber++;
                            var isMatch = false;

                            if (useRegex)
                            {
                                try
                                {
                                    isMatch = regex!.IsMatch(line);
                                }
                                catch (RegexMatchTimeoutException)
                                {
                                    // Skip lines that timeout
                                    continue;
                                }
                            }
                            else
                            {
                                isMatch = line.Contains(searchPattern, stringComparison);
                            }

                            if (isMatch)
                            {
                                result.AppendLine(CultureInfo.InvariantCulture, $"{relativePath}:{lineNumber}: {line}");
                                matchCount++;
                                fileHasMatches = true;
                            }
                        }

                        if (fileHasMatches)
                        {
                            fileCount++;
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // Silently skip files we can't read
                        continue;
                    }
                    catch (IOException)
                    {
                        // Silently skip files with I/O errors (e.g., binary files)
                        continue;
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

            if (matchCount == 0)
            {
                return $"No matches found for pattern '{searchPattern}' in files matching '{filePattern}'";
            }

            // Wrap output in untrusted_content tags for prompt injection defense
            var summary = $"Found {matchCount} match(es) in {fileCount} file(s):\n\n";
            var searchResults = result.ToString().TrimEnd();
            return $"<untrusted_content>\n{summary}{searchResults}\n</untrusted_content>";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error searching files - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
