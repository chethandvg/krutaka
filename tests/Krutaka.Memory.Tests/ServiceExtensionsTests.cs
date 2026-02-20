using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Memory.Tests;

/// <summary>
/// Tests for Krutaka.Memory service registration via AddMemory.
/// Validates singleton behaviour and configuration binding.
/// </summary>
public sealed class ServiceExtensionsTests : IDisposable
{
    // Use a unique in-memory SQLite path per test run to avoid shared state
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"krutaka-test-{Guid.NewGuid():N}.db");

    private ServiceProvider BuildProvider(Action<MemoryOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddMemory(o =>
        {
            o.DatabasePath = _dbPath;
            configure?.Invoke(o);
        });
        return services.BuildServiceProvider();
    }

    public void Dispose()
    {
        if (File.Exists(_dbPath))
        {
            File.Delete(_dbPath);
        }
    }

    // ── service resolution ────────────────────────────────────────────────────

    [Fact]
    public void AddMemory_Should_RegisterIMemoryService()
    {
        using var sp = BuildProvider();
        sp.GetService<IMemoryService>().Should().NotBeNull();
    }

    [Fact]
    public void AddMemory_Should_RegisterMemoryOptions()
    {
        using var sp = BuildProvider();
        sp.GetService<MemoryOptions>().Should().NotBeNull();
    }

    [Fact]
    public void AddMemory_Should_RegisterMemoryFileService()
    {
        using var sp = BuildProvider();
        sp.GetService<MemoryFileService>().Should().NotBeNull();
    }

    [Fact]
    public void AddMemory_Should_RegisterDailyLogService()
    {
        using var sp = BuildProvider();
        sp.GetService<DailyLogService>().Should().NotBeNull();
    }

    [Fact]
    public void AddMemory_Should_RegisterMemoryTools()
    {
        using var sp = BuildProvider();
        var tools = sp.GetServices<ITool>().ToList();
        tools.Should().NotBeEmpty("memory tools should be registered as ITool");
    }

    // ── singleton verification ────────────────────────────────────────────────

    [Fact]
    public void AddMemory_IMemoryService_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<IMemoryService>();
        var b = sp.GetRequiredService<IMemoryService>();
        a.Should().BeSameAs(b);
    }

    [Fact]
    public void AddMemory_MemoryOptions_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<MemoryOptions>();
        var b = sp.GetRequiredService<MemoryOptions>();
        a.Should().BeSameAs(b);
    }

    // ── configuration binding ─────────────────────────────────────────────────

    [Fact]
    public void AddMemory_Should_ApplyConfigureOptionsCallback()
    {
        using var sp = BuildProvider(o => o.ChunkSizeTokens = 250);
        var opts = sp.GetRequiredService<MemoryOptions>();
        opts.ChunkSizeTokens.Should().Be(250);
    }

    [Fact]
    public void AddMemory_Should_UseDefaultOptions_WhenConfigureIsNull()
    {
        var services = new ServiceCollection();
        // Override the DB path so the default path isn't used; still verify other defaults
        services.AddMemory(o => o.DatabasePath = _dbPath);
        using var sp = services.BuildServiceProvider();

        var opts = sp.GetRequiredService<MemoryOptions>();
        opts.ChunkSizeTokens.Should().Be(500, "default chunk size is 500");
        opts.ChunkOverlapTokens.Should().Be(50, "default overlap is 50");
    }
}
