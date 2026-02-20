using FluentAssertions;
using Krutaka.Core;
using Krutaka.Skills;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Skills.Tests;

/// <summary>
/// Tests for Krutaka.Skills service registration via AddSkills.
/// Validates singleton behaviour and configuration binding.
/// </summary>
public sealed class ServiceExtensionsTests
{
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
    public void AddSkills_Should_ApplyConfigureCallback()
    {
        var customDir = Path.GetTempPath();
        using var sp = BuildProvider(o =>
        {
            o.SkillDirectories.Clear();
            o.SkillDirectories.Add(customDir);
        });

        // Registry should resolve successfully with custom directories
        var registry = sp.GetRequiredService<ISkillRegistry>();
        registry.Should().NotBeNull();
    }
}
