#pragma warning disable CA2007 // Do not directly await a Task in tests
using System.Runtime.CompilerServices;
using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for AutonomyLevelOptions, AutonomyLevelProvider, and orchestrator integration.
/// Covers configuration parsing, startup validation, auto-approval matrix, immutability,
/// backward compatibility, and audit logging.
/// </summary>
public sealed class AutonomyLevelProviderTests
{
    // ── AutonomyLevelOptions ──────────────────────────────────────────────────

    [Fact]
    public void AutonomyLevelOptions_Should_DefaultToGuided()
    {
        var opts = new AutonomyLevelOptions();
        opts.Level.Should().Be(AutonomyLevel.Guided);
    }

    [Fact]
    public void AutonomyLevelOptions_Should_DefaultAllowAutonomousModeToFalse()
    {
        var opts = new AutonomyLevelOptions();
        opts.AllowAutonomousMode.Should().BeFalse();
    }

    [Theory]
    [InlineData(AutonomyLevel.Supervised)]
    [InlineData(AutonomyLevel.Guided)]
    [InlineData(AutonomyLevel.SemiAutonomous)]
    public void AutonomyLevelOptions_Validate_Should_NotThrow_ForNonAutonomousLevels(AutonomyLevel level)
    {
        var opts = new AutonomyLevelOptions { Level = level };
        var act = () => opts.Validate();
        act.Should().NotThrow();
    }

    [Fact]
    public void AutonomyLevelOptions_Validate_Should_NotThrow_WhenAutonomousWithOptIn()
    {
        var opts = new AutonomyLevelOptions { Level = AutonomyLevel.Autonomous, AllowAutonomousMode = true };
        var act = () => opts.Validate();
        act.Should().NotThrow();
    }

    [Fact]
    public void AutonomyLevelOptions_Validate_Should_ThrowInvalidOperationException_WhenAutonomousWithoutOptIn()
    {
        var opts = new AutonomyLevelOptions { Level = AutonomyLevel.Autonomous };
        var act = () => opts.Validate();
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*AllowAutonomousMode*");
    }

    // ── AutonomyLevelProvider construction ───────────────────────────────────

    [Fact]
    public void AutonomyLevelProvider_Constructor_Should_ThrowArgumentNullException_WhenOptionsIsNull()
    {
        var act = () => new AutonomyLevelProvider(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void AutonomyLevelProvider_Constructor_Should_ThrowInvalidOperationException_WhenAutonomousWithoutOptIn()
    {
        var opts = new AutonomyLevelOptions { Level = AutonomyLevel.Autonomous };
        var act = () => new AutonomyLevelProvider(opts);
        act.Should().Throw<InvalidOperationException>();
    }

    [Theory]
    [InlineData(AutonomyLevel.Supervised)]
    [InlineData(AutonomyLevel.Guided)]
    [InlineData(AutonomyLevel.SemiAutonomous)]
    [InlineData(AutonomyLevel.Autonomous)]
    public void AutonomyLevelProvider_GetLevel_Should_ReturnConfiguredLevel(AutonomyLevel level)
    {
        var opts = new AutonomyLevelOptions
        {
            Level = level,
            AllowAutonomousMode = level == AutonomyLevel.Autonomous
        };
        var provider = new AutonomyLevelProvider(opts);
        provider.GetLevel().Should().Be(level);
    }

    // ── Immutability (S9) ─────────────────────────────────────────────────────

    [Fact]
    public void AutonomyLevelProvider_Level_Should_BeImmutableAfterConstruction()
    {
        var opts = new AutonomyLevelOptions { Level = AutonomyLevel.Guided };
        var provider = new AutonomyLevelProvider(opts);

        // Mutate options after construction — should NOT affect provider
        opts.Level = AutonomyLevel.Autonomous;

        provider.GetLevel().Should().Be(AutonomyLevel.Guided);
    }

    // ── Auto-approval matrix: 4 levels × (Safe / Approval-Required) ──────────

    // Level 0 — Supervised: auto-approve nothing
    [Theory]
    [InlineData(false)] // Safe tier
    [InlineData(true)]  // Approval-required tier
    public void ShouldAutoApprove_Should_ReturnFalse_AtSupervisedLevel(bool isApprovalRequired)
    {
        var provider = CreateProvider(AutonomyLevel.Supervised);
        provider.ShouldAutoApprove("any_tool", isApprovalRequired).Should().BeFalse();
    }

    // Level 1 — Guided: auto-approve Safe only
    [Fact]
    public void ShouldAutoApprove_Should_ReturnTrue_AtGuidedLevel_ForSafeTool()
    {
        var provider = CreateProvider(AutonomyLevel.Guided);
        provider.ShouldAutoApprove("read_file", isApprovalRequired: false).Should().BeTrue();
    }

    [Theory]
    [InlineData("write_file")]
    [InlineData("edit_file")]
    [InlineData("run_command")]
    public void ShouldAutoApprove_Should_ReturnFalse_AtGuidedLevel_ForApprovalRequiredTool(string toolName)
    {
        var provider = CreateProvider(AutonomyLevel.Guided);
        provider.ShouldAutoApprove(toolName, isApprovalRequired: true).Should().BeFalse();
    }

    // Level 2 — SemiAutonomous: auto-approve Safe + Moderate (all non-Dangerous)
    [Fact]
    public void ShouldAutoApprove_Should_ReturnTrue_AtSemiAutonomousLevel_ForSafeTool()
    {
        var provider = CreateProvider(AutonomyLevel.SemiAutonomous);
        provider.ShouldAutoApprove("read_file", isApprovalRequired: false).Should().BeTrue();
    }

    [Fact]
    public void ShouldAutoApprove_Should_ReturnTrue_AtSemiAutonomousLevel_ForApprovalRequiredTool()
    {
        var provider = CreateProvider(AutonomyLevel.SemiAutonomous);
        provider.ShouldAutoApprove("write_file", isApprovalRequired: true).Should().BeTrue();
    }

    // Level 3 — Autonomous: auto-approve Safe + Moderate + Elevated
    [Fact]
    public void ShouldAutoApprove_Should_ReturnTrue_AtAutonomousLevel_ForSafeTool()
    {
        var provider = CreateProvider(AutonomyLevel.Autonomous);
        provider.ShouldAutoApprove("read_file", isApprovalRequired: false).Should().BeTrue();
    }

    [Fact]
    public void ShouldAutoApprove_Should_ReturnTrue_AtAutonomousLevel_ForApprovalRequiredTool()
    {
        var provider = CreateProvider(AutonomyLevel.Autonomous);
        provider.ShouldAutoApprove("write_file", isApprovalRequired: true).Should().BeTrue();
    }

    // Full 4×2 matrix as Theory (8 core cases + boundary)
    [Theory]
    [InlineData(AutonomyLevel.Supervised, false, false)]
    [InlineData(AutonomyLevel.Supervised, true,  false)]
    [InlineData(AutonomyLevel.Guided,     false, true)]
    [InlineData(AutonomyLevel.Guided,     true,  false)]
    [InlineData(AutonomyLevel.SemiAutonomous, false, true)]
    [InlineData(AutonomyLevel.SemiAutonomous, true,  true)]
    [InlineData(AutonomyLevel.Autonomous, false, true)]
    [InlineData(AutonomyLevel.Autonomous, true,  true)]
    public void ShouldAutoApprove_Should_MatchExpectedMatrix(
        AutonomyLevel level, bool isApprovalRequired, bool expectedResult)
    {
        var provider = CreateProvider(level);
        provider.ShouldAutoApprove("tool_name", isApprovalRequired).Should().Be(expectedResult);
    }

    // ── Default fallback: missing config → Guided ─────────────────────────────

    [Fact]
    public void AutonomyLevelProvider_Should_DefaultToGuided_WhenOptionsAreDefault()
    {
        var provider = new AutonomyLevelProvider(new AutonomyLevelOptions());
        provider.GetLevel().Should().Be(AutonomyLevel.Guided);
        // Guided: auto-approve Safe, prompt approval-required
        provider.ShouldAutoApprove("read_file", false).Should().BeTrue();
        provider.ShouldAutoApprove("write_file", true).Should().BeFalse();
    }

    // ── Orchestrator integration ──────────────────────────────────────────────

    [Fact]
    public async Task Orchestrator_Should_SkipApprovalPrompt_WhenAutonomyLevelAutoApproves()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");
        claudeClient.AddFinalResponse("completed", "end_turn");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "ok");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("write_file", true); // normally needs approval

        // SemiAutonomous: auto-approve all non-Dangerous tools
        var autonomyProvider = CreateProvider(AutonomyLevel.SemiAutonomous);

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            autonomyLevelProvider: autonomyProvider);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("do something", "system"))
        {
            events.Add(evt);
        }

        // Assert: no HumanApprovalRequired event should have been emitted
        events.Should().NotContain(e => e is HumanApprovalRequired);
        events.Should().Contain(e => e is ToolCallCompleted);
    }

    [Fact]
    public async Task Orchestrator_Should_StillPrompt_WhenApprovalRequired_AndProviderReturnsFalse()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");
        claudeClient.AddFinalResponse("completed", "end_turn");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "ok");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("write_file", true);

        // Guided: does NOT auto-approve approval-required tools
        var autonomyProvider = CreateProvider(AutonomyLevel.Guided);

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            approvalTimeoutSeconds: 1, // short timeout for test
            autonomyLevelProvider: autonomyProvider);

        // Act — expect timeout since no one approves
        var events = new List<AgentEvent>();
        var act = async () =>
        {
            await foreach (var evt in orchestrator.RunAsync("do something", "system"))
            {
                events.Add(evt);
            }
        };

        // Assert: HumanApprovalRequired event is emitted, timeout thrown
        await act.Should().ThrowAsync<TimeoutException>();
        events.Should().Contain(e => e is HumanApprovalRequired);
    }

    [Fact]
    public async Task Orchestrator_Should_PreserveExistingBehavior_WhenProviderIsNull()
    {
        // Arrange — Safe tool, no provider, should auto-execute
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("read_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");
        claudeClient.AddFinalResponse("completed", "end_turn");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("read_file", "file contents");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("read_file", false); // Safe — no approval needed

        // null provider — existing behavior preserved
        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            autonomyLevelProvider: null);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("read something", "system"))
        {
            events.Add(evt);
        }

        // Assert: no approval required for Safe tools regardless of provider
        events.Should().NotContain(e => e is HumanApprovalRequired);
        events.Should().Contain(e => e is ToolCallCompleted);
    }

    [Fact]
    public async Task Orchestrator_NullProvider_ApprovalRequired_Should_StillPrompt()
    {
        // Arrange — Approval-required tool, no provider: should still prompt (existing behavior)
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "ok");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("write_file", true);

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            approvalTimeoutSeconds: 1,
            autonomyLevelProvider: null); // no provider

        // Act
        var events = new List<AgentEvent>();
        var act = async () =>
        {
            await foreach (var evt in orchestrator.RunAsync("write something", "system"))
            {
                events.Add(evt);
            }
        };

        // Assert: still prompts (existing behavior unchanged)
        await act.Should().ThrowAsync<TimeoutException>();
        events.Should().Contain(e => e is HumanApprovalRequired);
    }

    // ── Audit logging ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Orchestrator_Should_LogAutoApproval_WhenAutonomyLevelAutoApproves()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");
        claudeClient.AddFinalResponse("completed", "end_turn");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "ok");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("write_file", true);

        var auditLogger = new MockAuditLogger();
        var autonomyProvider = CreateProvider(AutonomyLevel.SemiAutonomous);

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            auditLogger: auditLogger,
            autonomyLevelProvider: autonomyProvider);

        // Act
        await foreach (var _ in orchestrator.RunAsync("do something", "system"))
        {
        }

        // Assert: a ToolAutoApprovedEvent was logged
        auditLogger.Events.Should().ContainSingle(e => e is ToolAutoApprovedEvent);
        var autoApproveEvent = (ToolAutoApprovedEvent)auditLogger.Events.Single(e => e is ToolAutoApprovedEvent);
        autoApproveEvent.ToolName.Should().Be("write_file");
        autoApproveEvent.Level.Should().Be(AutonomyLevel.SemiAutonomous);
        autoApproveEvent.WasApprovalRequired.Should().BeTrue();
    }

    [Fact]
    public async Task Orchestrator_Should_NotLogAutoApproval_WhenToolIsNotAutoApproved()
    {
        // Arrange: Guided level, approval-required tool → no auto-approval
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "ok");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("write_file", true);

        var auditLogger = new MockAuditLogger();
        var autonomyProvider = CreateProvider(AutonomyLevel.Guided); // Guided: does NOT auto-approve

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            auditLogger: auditLogger,
            approvalTimeoutSeconds: 1,
            autonomyLevelProvider: autonomyProvider);

        // Act
        var act = async () =>
        {
            await foreach (var _ in orchestrator.RunAsync("do something", "system"))
            {
            }
        };
        await act.Should().ThrowAsync<TimeoutException>();

        // Assert: no auto-approved event logged
        auditLogger.Events.Should().NotContain(e => e is ToolAutoApprovedEvent);
    }

    // ── Supervised level prompts for Safe tools ───────────────────────────────

    [Fact]
    public async Task Orchestrator_Should_Prompt_ForSafeTool_WhenAutonomyLevelIsSupervised()
    {
        // Arrange: Supervised level, Safe tool — should still prompt (every action requires approval)
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("read_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("read_file", "file contents");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("read_file", false); // Safe tier — policy says no approval needed

        var autonomyProvider = CreateProvider(AutonomyLevel.Supervised);

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            approvalTimeoutSeconds: 1, // short timeout for test
            autonomyLevelProvider: autonomyProvider);

        // Act — expect timeout since no one approves
        var events = new List<AgentEvent>();
        var act = async () =>
        {
            await foreach (var evt in orchestrator.RunAsync("read something", "system"))
            {
                events.Add(evt);
            }
        };

        // Assert: HumanApprovalRequired emitted despite Safe tier, because Supervised mode requires all approvals
        await act.Should().ThrowAsync<TimeoutException>();
        events.Should().Contain(e => e is HumanApprovalRequired);
    }

    // ── Audit: auto-approved tools are logged as Approved=true ───────────────

    [Fact]
    public async Task Orchestrator_Should_LogToolExecution_AsApproved_WhenAutoApproved()
    {
        // Arrange
        var claudeClient = new MockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "id1", "{}");
        claudeClient.AddFinalResponse("done", "tool_use");
        claudeClient.AddFinalResponse("completed", "end_turn");

        var toolRegistry = new MockToolRegistry();
        toolRegistry.AddTool("write_file", "ok");

        var securityPolicy = new MockSecurityPolicy();
        securityPolicy.SetApprovalRequired("write_file", true);

        var auditLogger = new MockAuditLogger();
        var autonomyProvider = CreateProvider(AutonomyLevel.SemiAutonomous);

        // Provide CorrelationContext so that LogToolExecution is actually called
        var correlationContext = new CorrelationContext(Guid.NewGuid());

        using var orchestrator = new AgentOrchestrator(
            claudeClient: claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: securityPolicy,
            auditLogger: auditLogger,
            correlationContext: correlationContext,
            autonomyLevelProvider: autonomyProvider);

        // Act
        await foreach (var _ in orchestrator.RunAsync("do something", "system"))
        {
        }

        // Assert: tool execution was logged as approved=true (not as unapproved)
        auditLogger.ToolExecutionLogs.Should().ContainSingle();
        auditLogger.ToolExecutionLogs[0].Approved.Should().BeTrue(
            "auto-approved tools must be recorded as approved in LogToolExecution");
        auditLogger.ToolExecutionLogs[0].ToolName.Should().Be("write_file");
    }

    // ── Helper factory ────────────────────────────────────────────────────────

    private static AutonomyLevelProvider CreateProvider(AutonomyLevel level)
    {
        return new AutonomyLevelProvider(new AutonomyLevelOptions
        {
            Level = level,
            AllowAutonomousMode = level == AutonomyLevel.Autonomous
        });
    }

    // ── Mock implementations ──────────────────────────────────────────────────

    private sealed class MockClaudeClient : IClaudeClient
    {
        private readonly List<List<AgentEvent>> _eventBatches = [];
        private int _callIndex;

        public void AddToolCallStarted(string name, string id, string input)
        {
            EnsureCurrentBatch();
            _eventBatches[^1].Add(new ToolCallStarted(name, id, input));
        }

        public void AddFinalResponse(string content, string stopReason)
        {
            EnsureCurrentBatch();
            _eventBatches[^1].Add(new FinalResponse(content, stopReason));
            _eventBatches.Add([]);
        }

        private void EnsureCurrentBatch()
        {
            if (_eventBatches.Count == 0)
            {
                _eventBatches.Add([]);
            }
        }

        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            if (_callIndex < _eventBatches.Count)
            {
                var batch = _eventBatches[_callIndex++];
                foreach (var evt in batch)
                {
                    yield return evt;
                }
            }
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken = default)
            => Task.FromResult(100);
    }

    private sealed class MockToolRegistry : IToolRegistry
    {
        private readonly Dictionary<string, string> _tools = [];

        public void AddTool(string name, string result)
        {
            _tools[name] = result;
        }

        public void Register(ITool tool) { }

        public object GetToolDefinitions() => Array.Empty<object>();

        public Task<string> ExecuteAsync(string name, JsonElement input, CancellationToken cancellationToken)
        {
            return Task.FromResult(_tools.TryGetValue(name, out var result) ? result : "executed");
        }
    }

    private sealed class MockSecurityPolicy : ISecurityPolicy
    {
        private readonly Dictionary<string, bool> _approvalRequirements = [];

        public void SetApprovalRequired(string toolName, bool required)
        {
            _approvalRequirements[toolName] = required;
        }

        public bool IsApprovalRequired(string toolName)
            => _approvalRequirements.TryGetValue(toolName, out var required) && required;

        public string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null) => path;

        public void ValidateCommand(string executable, IEnumerable<string> arguments, CorrelationContext? correlationContext = null) { }

        public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
            => new Dictionary<string, string?>(environment);
    }

    private sealed class MockAuditLogger : IAuditLogger
    {
        public List<AuditEvent> Events { get; } = [];
        public List<(string ToolName, bool Approved)> ToolExecutionLogs { get; } = [];

        public void Log(AuditEvent auditEvent) => Events.Add(auditEvent);

        public void LogUserInput(CorrelationContext correlationContext, string content) { }
        public void LogClaudeApiRequest(CorrelationContext correlationContext, string model, int tokenCount, int toolCount) { }
        public void LogClaudeApiResponse(CorrelationContext correlationContext, string stopReason, int inputTokens, int outputTokens) { }

        public void LogToolExecution(CorrelationContext correlationContext, string toolName, bool approved, bool alwaysApprove, long durationMs, int resultLength, string? errorMessage = null)
        {
            ToolExecutionLogs.Add((toolName, approved));
        }

        public void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved) { }
        public void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context) { }
        public void LogCommandClassification(CorrelationContext correlationContext, string executable, string arguments, CommandRiskTier tier, bool autoApproved, string? trustedDirectory, string reason) { }
    }
}
