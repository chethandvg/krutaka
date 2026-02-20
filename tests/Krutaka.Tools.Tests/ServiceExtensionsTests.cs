using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for Krutaka.Tools service registration via AddAgentTools.
/// Validates singleton behaviour, configuration binding, and fail-fast validation.
/// </summary>
public sealed class ServiceExtensionsTests
{
    // ── helpers ──────────────────────────────────────────────────────────────

    private static ServiceProvider BuildProvider(Action<ToolOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuditLogger, NoOpAuditLogger>();
        // IClaudeClient is required by SessionFactory but is not registered by AddAgentTools
        // (it is registered by AddClaudeAI in the composition root)
        services.AddSingleton<IClaudeClient, NoOpClaudeClient>();
        services.AddAgentTools(configure);
        return services.BuildServiceProvider();
    }

    // ── service resolution ────────────────────────────────────────────────────

    [Fact]
    public void AddAgentTools_Should_RegisterISecurityPolicy()
    {
        using var sp = BuildProvider();
        sp.GetService<ISecurityPolicy>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterIAccessPolicyEngine()
    {
        using var sp = BuildProvider();
        sp.GetService<IAccessPolicyEngine>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterICommandRiskClassifier()
    {
        using var sp = BuildProvider();
        sp.GetService<ICommandRiskClassifier>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterICommandPolicy()
    {
        using var sp = BuildProvider();
        sp.GetService<ICommandPolicy>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterIFileOperations()
    {
        using var sp = BuildProvider();
        sp.GetService<IFileOperations>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterToolOptions()
    {
        using var sp = BuildProvider();
        sp.GetService<ToolOptions>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterIToolOptions()
    {
        using var sp = BuildProvider();
        sp.GetService<IToolOptions>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterISessionFactory()
    {
        using var sp = BuildProvider();
        sp.GetService<ISessionFactory>().Should().NotBeNull();
    }

    [Fact]
    public void AddAgentTools_Should_RegisterISessionManager()
    {
        // Note: ServiceProvider cannot be disposed synchronously here because SessionManager
        // only implements IAsyncDisposable. Resolving is sufficient to validate registration.
        var sp = BuildProvider();
        sp.GetService<ISessionManager>().Should().NotBeNull();
    }

    // ── singleton verification ────────────────────────────────────────────────

    [Fact]
    public void AddAgentTools_ISecurityPolicy_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<ISecurityPolicy>();
        var b = sp.GetRequiredService<ISecurityPolicy>();
        a.Should().BeSameAs(b);
    }

    [Fact]
    public void AddAgentTools_IAccessPolicyEngine_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<IAccessPolicyEngine>();
        var b = sp.GetRequiredService<IAccessPolicyEngine>();
        a.Should().BeSameAs(b);
    }

    [Fact]
    public void AddAgentTools_ToolOptions_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<ToolOptions>();
        var b = sp.GetRequiredService<ToolOptions>();
        a.Should().BeSameAs(b);
    }

    [Fact]
    public void AddAgentTools_IToolOptions_And_ToolOptions_Should_BeSameInstance()
    {
        using var sp = BuildProvider();
        var opts = sp.GetRequiredService<ToolOptions>();
        var iOpts = sp.GetRequiredService<IToolOptions>();
        opts.Should().BeSameAs(iOpts);
    }

    [Fact]
    public void AddAgentTools_ISessionFactory_Should_BeSingleton()
    {
        using var sp = BuildProvider();
        var a = sp.GetRequiredService<ISessionFactory>();
        var b = sp.GetRequiredService<ISessionFactory>();
        a.Should().BeSameAs(b);
    }

    // ── configuration binding ─────────────────────────────────────────────────

    [Fact]
    public void AddAgentTools_Should_ApplyConfigureOptionsCallback()
    {
        using var sp = BuildProvider(o =>
        {
            o.CommandTimeoutSeconds = 99;
            o.RequireApprovalForWrites = false;
        });

        var opts = sp.GetRequiredService<ToolOptions>();
        opts.CommandTimeoutSeconds.Should().Be(99);
        opts.RequireApprovalForWrites.Should().BeFalse();
    }

    [Fact]
    public void AddAgentTools_Should_UseDefaultOptions_WhenConfigureIsNull()
    {
        using var sp = BuildProvider();
        var opts = sp.GetRequiredService<ToolOptions>();
        opts.CommandTimeoutSeconds.Should().Be(30, "default timeout is 30 seconds");
        opts.RequireApprovalForWrites.Should().BeTrue("default requires approval");
    }

    // ── fail-fast validation ──────────────────────────────────────────────────

    [Fact]
    public void AddAgentTools_Should_ThrowInvalidOperationException_WhenAutoGrantPatternIsInvalid()
    {
        var services = new ServiceCollection();
        var action = () => services.AddAgentTools(o =>
        {
            o.CeilingDirectory = Path.GetTempPath();
            o.AutoGrantPatterns = ["[invalid-glob"];
        });

        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*AutoGrantPatterns*");
    }

    [Fact]
    public void AddAgentTools_Should_ThrowArgumentNullException_WhenServicesIsNull()
    {
        IServiceCollection? services = null;
        var action = () => services!.AddAgentTools();
        action.Should().Throw<ArgumentNullException>();
    }

    // ── per-session services are NOT singletons (created by SessionFactory) ───

    [Fact]
    public void AddAgentTools_ICommandApprovalCache_Should_NotBeRegisteredGlobally()
    {
        // Per-session components are created by SessionFactory, not global DI
        using var sp = BuildProvider();
        sp.GetService<ICommandApprovalCache>().Should().BeNull(
            "ICommandApprovalCache is per-session and created by SessionFactory, not registered globally");
    }

    [Fact]
    public void AddAgentTools_IToolRegistry_Should_NotBeRegisteredGlobally()
    {
        // Per-session tool registries are created by SessionFactory
        using var sp = BuildProvider();
        sp.GetService<IToolRegistry>().Should().BeNull(
            "IToolRegistry is per-session and created by SessionFactory, not registered globally");
    }

    // ── null audit logger stub ────────────────────────────────────────────────

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812", Justification = "Instantiated by DI")]
    private sealed class NoOpAuditLogger : IAuditLogger
    {
        public void Log(AuditEvent auditEvent) { }
        public void LogUserInput(CorrelationContext ctx, string content) { }
        public void LogClaudeApiRequest(CorrelationContext ctx, string model, int tokenCount, int toolCount) { }
        public void LogClaudeApiResponse(CorrelationContext ctx, string stopReason, int inputTokens, int outputTokens) { }
        public void LogToolExecution(CorrelationContext ctx, string toolName, bool approved, bool alwaysApprove, long durationMs, int resultLength, string? errorMessage = null) { }
        public void LogCompaction(CorrelationContext ctx, int beforeTokenCount, int afterTokenCount, int messagesRemoved) { }
        public void LogSecurityViolation(CorrelationContext ctx, string violationType, string blockedValue, string context) { }
        public void LogCommandClassification(CorrelationContext ctx, string executable, string arguments, CommandRiskTier tier, bool autoApproved, string? trustedDirectory, string reason) { }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812", Justification = "Instantiated by DI")]
    private sealed class NoOpClaudeClient : IClaudeClient
    {
        public IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools,
            CancellationToken cancellationToken) => AsyncEnumerable.Empty<AgentEvent>();

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken) => Task.FromResult(0);
    }
}
