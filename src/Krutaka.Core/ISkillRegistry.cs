namespace Krutaka.Core;

/// <summary>
/// Manages the collection of skills and provides metadata for progressive disclosure.
/// Skills are Markdown files with YAML frontmatter that modify agent behavior.
/// </summary>
public interface ISkillRegistry
{
    /// <summary>
    /// Gets metadata for all registered skills.
    /// Returns only name and description for progressive disclosure pattern.
    /// Full skill content is loaded on-demand when skill is invoked.
    /// </summary>
    /// <returns>A collection of skill metadata (name + description).</returns>
    IReadOnlyList<SkillMetadata> GetSkillMetadata();
}

/// <summary>
/// Metadata for a skill in the registry.
/// Used for progressive disclosure - only name and description are included in system prompt.
/// </summary>
public record SkillMetadata(
    string Name,
    string Description);
