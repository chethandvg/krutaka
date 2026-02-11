using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Krutaka.Core;

namespace Krutaka.Skills;

/// <summary>
/// Loads and parses skill files with YAML frontmatter.
/// </summary>
public class SkillLoader
{
    private static readonly IDeserializer YamlDeserializer = new DeserializerBuilder()
        .WithNamingConvention(HyphenatedNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    /// <summary>
    /// Loads a skill file and parses its YAML frontmatter.
    /// </summary>
    /// <param name="filePath">Path to the SKILL.md file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Skill metadata and full content.</returns>
#pragma warning disable CA1822 // Method is not static to support dependency injection and testability
    public async Task<(SkillMetadata Metadata, string FullContent)> LoadSkillAsync(
#pragma warning restore CA1822
        string filePath,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Skill file not found: {filePath}");
        }

        var content = await File.ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);
        var (frontmatter, body) = ParseYamlFrontmatter(content);

        var metadata = new SkillMetadata(
            Name: frontmatter.Name ?? throw new InvalidOperationException($"Skill file {filePath} is missing required 'name' field in frontmatter"),
            Description: frontmatter.Description ?? throw new InvalidOperationException($"Skill file {filePath} is missing required 'description' field in frontmatter"),
            FilePath: filePath,
            AllowedTools: frontmatter.AllowedTools?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList(),
            Model: frontmatter.Model,
            Version: frontmatter.Version
        );

        return (metadata, content);
    }

    /// <summary>
    /// Parses YAML frontmatter from a Markdown file.
    /// </summary>
    /// <param name="content">Full file content.</param>
    /// <returns>Frontmatter data and body content.</returns>
    private static (SkillFrontmatter Frontmatter, string Body) ParseYamlFrontmatter(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            throw new InvalidOperationException("Skill file content is empty");
        }

        // Check for YAML frontmatter delimiters
        if (!content.StartsWith("---", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Skill file is missing YAML frontmatter (must start with '---')");
        }

        // Find the closing delimiter
        var lines = content.Split('\n');
        var closingIndex = -1;
        for (var i = 1; i < lines.Length; i++)
        {
            if (lines[i].TrimEnd() == "---")
            {
                closingIndex = i;
                break;
            }
        }

        if (closingIndex == -1)
        {
            throw new InvalidOperationException("Skill file has malformed YAML frontmatter (missing closing '---')");
        }

        // Extract YAML content (between the delimiters)
        var yamlContent = string.Join('\n', lines[1..closingIndex]);
        var bodyContent = string.Join('\n', lines[(closingIndex + 1)..]);

        SkillFrontmatter frontmatter;
        try
        {
            frontmatter = YamlDeserializer.Deserialize<SkillFrontmatter>(yamlContent)
                ?? throw new InvalidOperationException("Failed to parse YAML frontmatter");
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException($"Failed to parse YAML frontmatter: {ex.Message}", ex);
        }

        return (frontmatter, bodyContent);
    }

    /// <summary>
    /// Internal representation of YAML frontmatter.
    /// YamlDotNet instantiates this class via reflection.
    /// </summary>
#pragma warning disable CA1812 // Class is instantiated via YamlDotNet reflection
    private sealed class SkillFrontmatter
#pragma warning restore CA1812
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? AllowedTools { get; set; }
        public string? Model { get; set; }
        public string? Version { get; set; }
    }
}
