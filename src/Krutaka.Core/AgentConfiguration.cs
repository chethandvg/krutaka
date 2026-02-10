using System.Text.Json.Serialization;

namespace Krutaka.Core;

/// <summary>
/// Configuration settings for the agent runtime.
/// Includes model settings, approval preferences, and directory paths.
/// </summary>
/// <param name="ModelId">The Claude model identifier (e.g., "claude-4-sonnet-20250514").</param>
/// <param name="MaxTokens">Maximum output tokens per response.</param>
/// <param name="Temperature">Sampling temperature (0.0-1.0).</param>
/// <param name="RequireApprovalForWrite">Whether to require human approval for write operations.</param>
/// <param name="RequireApprovalForExecute">Whether to require human approval for command execution (always true for security).</param>
/// <param name="AllowApprovalAlways">Whether to allow "Always approve" option for write tools in a session.</param>
/// <param name="ProjectRoot">The project root directory for file operations.</param>
/// <param name="ConfigDirectory">The agent configuration directory (defaults to ~/.krutaka).</param>
/// <param name="SessionDirectory">Directory for session JSONL files.</param>
/// <param name="SkillsDirectory">Directory containing skill markdown files.</param>
[method: JsonConstructor]
public sealed record AgentConfiguration(
    [property: JsonPropertyName("model_id")] string ModelId = "claude-4-sonnet-20250514",
    [property: JsonPropertyName("max_tokens")] int MaxTokens = 8192,
    [property: JsonPropertyName("temperature")] double Temperature = 0.7,
    [property: JsonPropertyName("require_approval_for_write")] bool RequireApprovalForWrite = true,
    [property: JsonPropertyName("require_approval_for_execute")] bool RequireApprovalForExecute = true,
    [property: JsonPropertyName("allow_approval_always")] bool AllowApprovalAlways = true,
    [property: JsonPropertyName("project_root")] string? ProjectRoot = null,
    [property: JsonPropertyName("config_directory")] string? ConfigDirectory = null,
    [property: JsonPropertyName("session_directory")] string? SessionDirectory = null,
    [property: JsonPropertyName("skills_directory")] string? SkillsDirectory = null
)
{
    /// <summary>
    /// Gets the configuration directory path, defaulting to ~/.krutaka if not specified.
    /// </summary>
    [JsonIgnore]
    public string ConfigDirectoryPath => ConfigDirectory ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".krutaka");

    /// <summary>
    /// Gets the session directory path, defaulting to ConfigDirectory/sessions if not specified.
    /// </summary>
    [JsonIgnore]
    public string SessionDirectoryPath => SessionDirectory ?? Path.Combine(ConfigDirectoryPath, "sessions");

    /// <summary>
    /// Gets the skills directory path, defaulting to ConfigDirectory/skills if not specified.
    /// </summary>
    [JsonIgnore]
    public string SkillsDirectoryPath => SkillsDirectory ?? Path.Combine(ConfigDirectoryPath, "skills");
}
