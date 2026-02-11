namespace Krutaka.Skills;

/// <summary>
/// Configuration options for the skill system.
/// </summary>
public class SkillOptions
{
    /// <summary>
    /// Gets the directories to scan for skills.
    /// Default directory is ./skills/.
    /// </summary>
    public IList<string> SkillDirectories { get; } = new List<string>();

    /// <summary>
    /// Adds default skill directories.
    /// </summary>
    public void AddDefaultDirectories()
    {
        // Local skills directory (project-relative)
        var localSkillsDir = Path.Combine(Directory.GetCurrentDirectory(), "skills");
        if (!SkillDirectories.Contains(localSkillsDir))
        {
            SkillDirectories.Add(localSkillsDir);
        }
    }
}
