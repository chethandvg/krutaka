namespace Krutaka.Skills;

/// <summary>
/// Configuration options for the skill system.
/// </summary>
public class SkillOptions
{
    /// <summary>
    /// Gets the directories to scan for skills.
    /// Default directories are ./skills/ and ~/.krutaka/skills/.
    /// </summary>
    public IList<string> SkillDirectories { get; } = new List<string>();

    /// <summary>
    /// Adds default skill directories.
    /// </summary>
    public void AddDefaultDirectories()
    {
        // Local skills directory
        var localSkillsDir = Path.Combine(Directory.GetCurrentDirectory(), "skills");
        if (!SkillDirectories.Contains(localSkillsDir))
        {
            SkillDirectories.Add(localSkillsDir);
        }

        // User-level skills directory
        var userSkillsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".krutaka",
            "skills"
        );
        if (!SkillDirectories.Contains(userSkillsDir))
        {
            SkillDirectories.Add(userSkillsDir);
        }
    }
}
