# Krutaka.Skills

Provides the skill system — loading, validating, and registering skill definition files that extend the agent's capabilities through structured YAML-based instructions.

## NuGet Dependencies

| Package | Purpose |
|---|---|
| `Microsoft.Extensions.DependencyInjection` | DI registration helpers |
| `YamlDotNet` | YAML frontmatter parsing |

## Key Responsibilities

- Load and parse skill definition files (`SKILL.md`) from configured directories
- Validate YAML frontmatter (required `name` and `description` fields, file size limits)
- Register skill metadata in `ISkillRegistry` for progressive disclosure
- Provide full skill content on demand via `ISkillRegistry.LoadFullContentAsync`
- Expose DI registration via `AddSkills()` extension method

> Skills are loaded from the file system at startup and registered with `ISkillRegistry`.

## Directory Layout

| Directory | Description | Key Files |
|---|---|---|
| `Core/` | Skill loading and registry implementation | `SkillLoader.cs`, `SkillRegistry.cs` |
| _(root)_ | Configuration and DI registration | `SkillOptions.cs`, `ServiceExtensions.cs` |

## Relationships

- **Depends on:** `Krutaka.Core` (interfaces: `ISkillRegistry`, records: `SkillMetadata`)
- **Depended on by:** `Krutaka.Console` (composition root)
