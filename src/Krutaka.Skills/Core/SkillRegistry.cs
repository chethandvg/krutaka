using Krutaka.Core;

namespace Krutaka.Skills;

/// <summary>
/// Manages the collection of skills and provides metadata for progressive disclosure.
/// </summary>
public class SkillRegistry : ISkillRegistry
{
    private readonly SkillLoader _loader;
    private readonly Dictionary<string, SkillMetadata> _metadataCache = new();
    private readonly List<string> _skillDirectories;

    /// <summary>
    /// Initializes a new instance of the <see cref="SkillRegistry"/> class.
    /// </summary>
    /// <param name="loader">The skill loader.</param>
    /// <param name="skillDirectories">Directories to scan for skills.</param>
    public SkillRegistry(SkillLoader loader, IEnumerable<string> skillDirectories)
    {
        _loader = loader;
        _skillDirectories = skillDirectories.ToList();
    }

    /// <summary>
    /// Loads skill metadata from all configured directories.
    /// Scans for SKILL.md files recursively.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task LoadMetadataAsync(CancellationToken cancellationToken = default)
    {
        _metadataCache.Clear();

        foreach (var directory in _skillDirectories)
        {
            if (!Directory.Exists(directory))
            {
                continue; // Skip non-existent directories
            }

            string[] skillFiles;
            try
            {
                skillFiles = Directory.GetFiles(directory, "SKILL.md", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                // Skip directories we don't have permission to access
                continue;
            }
            catch (PathTooLongException)
            {
                // Skip directories with paths that are too long
                continue;
            }
            catch (IOException)
            {
                // Skip directories with I/O errors
                continue;
            }

            foreach (var file in skillFiles)
            {
#pragma warning disable CA1031 // Do not catch general exception types - we want to continue loading other skills even if one fails
                try
                {
                    var (metadata, _) = await _loader.LoadSkillAsync(file, cancellationToken).ConfigureAwait(false);
                    
                    // Detect duplicate skill names
                    if (_metadataCache.ContainsKey(metadata.Name))
                    {
                        // Skip duplicate - keep the first one loaded (deterministic behavior)
                        continue;
                    }
                    
                    _metadataCache[metadata.Name] = metadata;
                }
                catch (Exception)
                {
                    // Silently skip skills that fail to load
                    // In production, this would use ILogger to log the error
                }
#pragma warning restore CA1031 // Do not catch general exception types
            }
        }
    }

    /// <summary>
    /// Gets metadata for all registered skills.
    /// Returns only name and description for progressive disclosure pattern.
    /// </summary>
    /// <returns>A collection of skill metadata.</returns>
    public IReadOnlyList<SkillMetadata> GetSkillMetadata()
    {
        return _metadataCache.Values.ToList();
    }

    /// <summary>
    /// Loads the full content of a skill by name.
    /// </summary>
    /// <param name="name">The skill name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The full skill content including frontmatter and body.</returns>
    public async Task<string> LoadFullContentAsync(string name, CancellationToken cancellationToken = default)
    {
        if (!_metadataCache.TryGetValue(name, out var metadata))
        {
            throw new KeyNotFoundException($"Skill not found: {name}");
        }

        // Validate file size before reading
        var fileInfo = new FileInfo(metadata.FilePath);
        if (fileInfo.Length > SkillLoader.MaxSkillFileSizeBytes)
        {
            throw new InvalidOperationException(
                $"Skill file size ({fileInfo.Length} bytes) exceeds maximum allowed size ({SkillLoader.MaxSkillFileSizeBytes} bytes): '{metadata.FilePath}'");
        }

        return await File.ReadAllTextAsync(metadata.FilePath, cancellationToken).ConfigureAwait(false);
    }
}
