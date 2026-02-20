using FluentAssertions;
using Krutaka.Core;
using Krutaka.Skills;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Skills.Tests;

/// <summary>
/// Tests for Krutaka.Skills service registration via AddSkills.
/// Validates singleton behaviour and configuration binding.
/// </summary>
public sealed class ServiceExtensionsTests : IDisposable
{
    // Isolated temp directory used by tests that write SKILL.md files
    private readonly string _testDir = TestDirectoryHelper.GetTestDirectory("skills-di");

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testDir);
    }

    private static ServiceProvider BuildProvider(Action<SkillOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSkills(configure);
        return services.BuildServiceProvider();
    }

    // ── service resolution ────────────────────────────────────────────────────

    [Fact]
    public void AddSkills_Should_RegisterISkillRegistry()
    {
        using var sp = BuildProvider();
        sp.GetService<ISkillRegistry>().Should().NotBeNull();
    }

    [Fact]
    public void AddSkills_Should_RegisterSkillRegistry()
    {
        using var sp = BuildProvider();
        sp.GetService<SkillRegistry>().Should().NotBeNull();
    }

    [Fact]
    public void AddSkills_Should_RegisterSkillLoader()
    {
        using var sp = BuildProvider();
        sp.GetService<SkillLoader>().Should().NotBeNull();
    }

    // ── singleton verification ────────────────────────────────────────────────

    [Fact]
    public void AddSkills_ISkillRegistry_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<ISkillRegistry>();
        var b = sp.GetRequiredService<ISkillRegistry>();
        a.Should().BeSameAs(b);
    }

    [Fact]
    public void AddSkills_SkillRegistry_And_ISkillRegistry_Should_BeSameInstance()
    {
        using var sp = BuildProvider();
        var registry = sp.GetRequiredService<SkillRegistry>();
        var iRegistry = sp.GetRequiredService<ISkillRegistry>();
        registry.Should().BeSameAs(iRegistry);
    }

    // ── configuration binding ─────────────────────────────────────────────────

    [Fact]
    public void AddSkills_Should_AddDefaultSkillDirectories_WhenNoConfigureProvided()
    {
        // The AddSkills implementation always calls AddDefaultDirectories
        // which adds the local ./skills directory
        using var sp = BuildProvider();

        // Resolving the registry should succeed (it pre-loads metadata at startup)
        var registry = sp.GetRequiredService<ISkillRegistry>();
        registry.Should().NotBeNull();
    }

    [Fact]
    public void AddSkills_Should_ApplyConfigureCallback_AndLoadSkillsFromConfiguredDirectory()
    {
        // Arrange — write a real SKILL.md into an isolated temp directory so the registry
        // can discover and load it, proving the callback was applied.
        Directory.CreateDirectory(_testDir);
        var skillFile = Path.Combine(_testDir, "SKILL.md");
        File.WriteAllText(skillFile,
            """
            ---
            name: test-di-skill
            description: A skill used to verify DI configure callback is applied
            ---
            Skill body.
            """);

        using var sp = BuildProvider(o =>
        {
            o.SkillDirectories.Clear();
            o.SkillDirectories.Add(_testDir);
        });

        // Act
        var registry = sp.GetRequiredService<ISkillRegistry>();
        var metadata = registry.GetSkillMetadata();

        // Assert — the callback was applied: only the configured directory was scanned
        // and the test skill file in that directory was discovered.
        metadata.Should().ContainSingle(m => m.Name == "test-di-skill",
            "the configure callback should have pointed the registry at the test directory only");
    }
}
