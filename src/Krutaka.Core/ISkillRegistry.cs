namespace Krutaka.Core;

/// <summary>
/// Manages the collection of skills and provides metadata for progressive disclosure.
/// Skills are Markdown files with YAML frontmatter that modify agent behavior.
/// </summary>
public interface ISkillRegistry
{
    /// <summary>
    /// Loads skill metadata from all configured directories.
    /// Scans for SKILL.md files recursively.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LoadMetadataAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets metadata for all registered skills.
    /// Returns only name and description for progressive disclosure pattern.
    /// Full skill content is loaded on-demand when skill is invoked.
    /// </summary>
    /// <returns>A collection of skill metadata (name + description).</returns>
    IReadOnlyList<SkillMetadata> GetSkillMetadata();

    /// <summary>
    /// Loads the full content of a skill by name.
    /// </summary>
    /// <param name="name">The skill name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The full skill content including frontmatter and body.</returns>
    Task<string> LoadFullContentAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>
/// Metadata for a skill in the registry.
/// Used for progressive disclosure - only name and description are included in system prompt.
/// </summary>
public record SkillMetadata(
    string Name,
    string Description,
    string FilePath,
    IReadOnlyList<string>? AllowedTools = null,
    string? Model = null,
    string? Version = null);
