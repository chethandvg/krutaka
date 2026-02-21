#pragma warning disable CA2007 // Do not directly await a Task in tests
using System.Runtime.CompilerServices;
using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for the <see cref="TaskBudgetTracker"/> implementation.
/// Covers thread safety, boundary conditions, percentage calculations, and snapshot accuracy.
/// </summary>
public sealed class TaskBudgetTrackerTests
{
    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenBudgetIsNull()
    {
        var act = () => new TaskBudgetTracker(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("budget");
    }

    [Fact]
    public void Constructor_Should_CreateTracker_WithDefaultBudget()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget());
        tracker.IsExhausted.Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // ITaskBudgetTracker implementation
    // -------------------------------------------------------------------------

    [Fact]
    public void TaskBudgetTracker_Should_ImplementITaskBudgetTracker()
    {
        ITaskBudgetTracker tracker = new TaskBudgetTracker(new TaskBudget());
        tracker.Should().BeAssignableTo<ITaskBudgetTracker>();
    }

    // -------------------------------------------------------------------------
    // TryConsume — basic behavior
    // -------------------------------------------------------------------------

    [Fact]
    public void TryConsume_Should_ReturnTrue_WhenWithinBudget()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 1000));
        tracker.TryConsume(BudgetDimension.Tokens, 500).Should().BeTrue();
    }

    [Fact]
    public void TryConsume_Should_ReturnFalse_WhenAmountExceedsLimit()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 200).Should().BeFalse();
    }

    [Fact]
    public void TryConsume_Should_ReturnFalse_WhenLimitAlreadyReached()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 100);
        tracker.TryConsume(BudgetDimension.Tokens, 1).Should().BeFalse();
    }

    [Fact]
    public void TryConsume_Should_AccumulateConsumption_AcrossMultipleCalls()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 40);
        tracker.TryConsume(BudgetDimension.Tokens, 40);
        tracker.TryConsume(BudgetDimension.Tokens, 20).Should().BeTrue();
        tracker.TryConsume(BudgetDimension.Tokens, 1).Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // TryConsume — boundary edge cases
    // -------------------------------------------------------------------------

    [Fact]
    public void TryConsume_Should_ReturnTrue_AtExactLimit()
    {
        // Consuming exactly to the limit should succeed
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 100).Should().BeTrue();
    }

    [Fact]
    public void TryConsume_Should_ReturnFalse_WhenAmountExceedsLimitByOne()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 101).Should().BeFalse();
    }

    [Fact]
    public void TryConsume_Should_Not_PartiallyConsume_WhenLimitWouldBeExceeded()
    {
        // If we have 50 left and try to consume 51, the counter must NOT change
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxToolCalls: 50));
        tracker.TryConsume(BudgetDimension.ToolCalls, 50);
        bool result = tracker.TryConsume(BudgetDimension.ToolCalls, 1);

        result.Should().BeFalse();
        var snapshot = tracker.GetSnapshot();
        snapshot.ToolCallsConsumed.Should().Be(50, "no partial consumption should occur");
    }

    [Fact]
    public void TryConsume_Should_ReturnFalse_WhenAmountWouldCauseIntegerOverflow()
    {
        // Budget is at int.MaxValue; consume all, then try to consume 1 more
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: int.MaxValue));
        tracker.TryConsume(BudgetDimension.Tokens, int.MaxValue);

        tracker.TryConsume(BudgetDimension.Tokens, 1).Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // TryConsume — invalid amount
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void TryConsume_Should_Throw_WhenAmountIsNotPositive(int invalidAmount)
    {
        var tracker = new TaskBudgetTracker(new TaskBudget());
        var act = () => tracker.TryConsume(BudgetDimension.Tokens, invalidAmount);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    // -------------------------------------------------------------------------
    // TryConsume — each dimension independently tracked
    // -------------------------------------------------------------------------

    [Fact]
    public void TryConsume_Tokens_Should_NotAffect_OtherDimensions()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 10, MaxToolCalls: 10, MaxFilesModified: 10, MaxProcessesSpawned: 10));

        tracker.TryConsume(BudgetDimension.Tokens, 10);

        var snapshot = tracker.GetSnapshot();
        snapshot.TokensConsumed.Should().Be(10);
        snapshot.ToolCallsConsumed.Should().Be(0);
        snapshot.FilesModified.Should().Be(0);
        snapshot.ProcessesSpawned.Should().Be(0);
    }

    [Fact]
    public void TryConsume_ToolCalls_Should_NotAffect_OtherDimensions()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 10, MaxToolCalls: 5, MaxFilesModified: 10, MaxProcessesSpawned: 10));

        tracker.TryConsume(BudgetDimension.ToolCalls, 5);

        var snapshot = tracker.GetSnapshot();
        snapshot.ToolCallsConsumed.Should().Be(5);
        snapshot.TokensConsumed.Should().Be(0);
        snapshot.FilesModified.Should().Be(0);
        snapshot.ProcessesSpawned.Should().Be(0);
    }

    [Fact]
    public void TryConsume_FilesModified_Should_NotAffect_OtherDimensions()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxFilesModified: 3));
        tracker.TryConsume(BudgetDimension.FilesModified, 3);

        var snapshot = tracker.GetSnapshot();
        snapshot.FilesModified.Should().Be(3);
        snapshot.TokensConsumed.Should().Be(0);
        snapshot.ToolCallsConsumed.Should().Be(0);
        snapshot.ProcessesSpawned.Should().Be(0);
    }

    [Fact]
    public void TryConsume_ProcessesSpawned_Should_NotAffect_OtherDimensions()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxProcessesSpawned: 2));
        tracker.TryConsume(BudgetDimension.ProcessesSpawned, 2);

        var snapshot = tracker.GetSnapshot();
        snapshot.ProcessesSpawned.Should().Be(2);
        snapshot.TokensConsumed.Should().Be(0);
        snapshot.ToolCallsConsumed.Should().Be(0);
        snapshot.FilesModified.Should().Be(0);
    }

    // -------------------------------------------------------------------------
    // IsExhausted
    // -------------------------------------------------------------------------

    [Fact]
    public void IsExhausted_Should_BeFalse_Initially()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget());
        tracker.IsExhausted.Should().BeFalse();
    }

    [Fact]
    public void IsExhausted_Should_BeTrue_WhenTokenBudgetReached()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 100);
        tracker.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_BeTrue_WhenToolCallBudgetReached()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxToolCalls: 5));
        tracker.TryConsume(BudgetDimension.ToolCalls, 5);
        tracker.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_BeTrue_WhenFilesModifiedBudgetReached()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxFilesModified: 3));
        tracker.TryConsume(BudgetDimension.FilesModified, 3);
        tracker.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_BeTrue_WhenProcessesSpawnedBudgetReached()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxProcessesSpawned: 2));
        tracker.TryConsume(BudgetDimension.ProcessesSpawned, 2);
        tracker.IsExhausted.Should().BeTrue();
    }

    [Fact]
    public void IsExhausted_Should_BeFalse_WhenOnlyOneExhaustDimensionAndOthersAreNot()
    {
        // All dimensions at default limits; only tokens exhausted
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 100, MaxToolCalls: 50, MaxFilesModified: 10, MaxProcessesSpawned: 5));
        tracker.TryConsume(BudgetDimension.Tokens, 50); // 50% used
        tracker.IsExhausted.Should().BeFalse();
    }

    // -------------------------------------------------------------------------
    // GetSnapshot — accuracy
    // -------------------------------------------------------------------------

    [Fact]
    public void GetSnapshot_Should_ReflectZeroConsumption_Initially()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 1000, MaxToolCalls: 100, MaxFilesModified: 20, MaxProcessesSpawned: 10));

        var snapshot = tracker.GetSnapshot();
        snapshot.TokensConsumed.Should().Be(0);
        snapshot.ToolCallsConsumed.Should().Be(0);
        snapshot.FilesModified.Should().Be(0);
        snapshot.ProcessesSpawned.Should().Be(0);
        snapshot.TokensPercentage.Should().Be(0.0);
        snapshot.ToolCallsPercentage.Should().Be(0.0);
        snapshot.FilesModifiedPercentage.Should().Be(0.0);
        snapshot.ProcessesSpawnedPercentage.Should().Be(0.0);
    }

    [Fact]
    public void GetSnapshot_Should_ReflectCurrentConsumption_AfterMultipleConsumesCalls()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 1000, MaxToolCalls: 10, MaxFilesModified: 20, MaxProcessesSpawned: 5));

        tracker.TryConsume(BudgetDimension.Tokens, 500);
        tracker.TryConsume(BudgetDimension.ToolCalls, 3);
        tracker.TryConsume(BudgetDimension.FilesModified, 4);
        tracker.TryConsume(BudgetDimension.ProcessesSpawned, 1);

        var snapshot = tracker.GetSnapshot();
        snapshot.TokensConsumed.Should().Be(500);
        snapshot.ToolCallsConsumed.Should().Be(3);
        snapshot.FilesModified.Should().Be(4);
        snapshot.ProcessesSpawned.Should().Be(1);
    }

    [Fact]
    public void GetSnapshot_Should_HaveCorrectPercentages()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(
            MaxClaudeTokens: 1000, MaxToolCalls: 10, MaxFilesModified: 20, MaxProcessesSpawned: 5));

        tracker.TryConsume(BudgetDimension.Tokens, 500);
        tracker.TryConsume(BudgetDimension.ToolCalls, 3);
        tracker.TryConsume(BudgetDimension.FilesModified, 10);
        tracker.TryConsume(BudgetDimension.ProcessesSpawned, 5);

        var snapshot = tracker.GetSnapshot();
        snapshot.TokensPercentage.Should().BeApproximately(0.5, 1e-9);
        snapshot.ToolCallsPercentage.Should().BeApproximately(0.3, 1e-9);
        snapshot.FilesModifiedPercentage.Should().BeApproximately(0.5, 1e-9);
        snapshot.ProcessesSpawnedPercentage.Should().BeApproximately(1.0, 1e-9);
    }

    [Fact]
    public void GetSnapshot_Should_ShowFullPercentage_WhenLimitReached()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 100);

        var snapshot = tracker.GetSnapshot();
        snapshot.TokensPercentage.Should().BeApproximately(1.0, 1e-9);
    }

    // -------------------------------------------------------------------------
    // GetPercentage helper
    // -------------------------------------------------------------------------

    [Fact]
    public void GetPercentage_Should_ReturnCorrectValue_AfterConsumption()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 1000));
        tracker.TryConsume(BudgetDimension.Tokens, 800);

        tracker.GetPercentage(BudgetDimension.Tokens).Should().BeApproximately(0.8, 1e-9);
    }

    [Fact]
    public void GetPercentage_Should_ReturnZero_ForEmptyDimension()
    {
        var tracker = new TaskBudgetTracker(new TaskBudget());
        tracker.GetPercentage(BudgetDimension.ToolCalls).Should().BeApproximately(0.0, 1e-9);
    }

    // -------------------------------------------------------------------------
    // Thread safety
    // -------------------------------------------------------------------------

    [Fact]
    public async Task TryConsume_Should_BeThreadSafe_WhenCalledConcurrently()
    {
        const int limit = 100;
        const int taskCount = 200; // More tasks than budget allows

        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: limit));
        int successCount = 0;

        var tasks = Enumerable.Range(0, taskCount).Select(_ => Task.Run(() =>
        {
            if (tracker.TryConsume(BudgetDimension.Tokens, 1))
            {
                Interlocked.Increment(ref successCount);
            }
        })).ToArray();

        await Task.WhenAll(tasks);

        // Exactly 'limit' tasks should have succeeded
        successCount.Should().Be(limit);
        var snapshot = tracker.GetSnapshot();
        snapshot.TokensConsumed.Should().Be(limit);
    }

    [Fact]
    public async Task TryConsume_Should_NeverExceedLimit_UnderConcurrentLoad()
    {
        const int limit = 100;
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxToolCalls: limit));

        var tasks = Enumerable.Range(0, 200).Select(_ => Task.Run(() =>
        {
            tracker.TryConsume(BudgetDimension.ToolCalls, 1);
        })).ToArray();

        await Task.WhenAll(tasks);

        var snapshot = tracker.GetSnapshot();
        snapshot.ToolCallsConsumed.Should().BeLessThanOrEqualTo(limit,
            "concurrent consumes must never exceed the budget limit");
    }
}

/// <summary>
/// Integration tests verifying that <see cref="AgentOrchestrator"/> enforces the task budget
/// using <see cref="TaskBudgetTracker"/>, including warning events, exhaustion events, and
/// loop termination on budget exhaustion.
/// </summary>
public sealed class AgentOrchestratorBudgetTests
{
    // -------------------------------------------------------------------------
    // Backward compatibility: null tracker
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_WorkNormally_WhenBudgetTrackerIsNull()
    {
        var claudeClient = new BudgetMockClaudeClient();
        claudeClient.AddFinalResponse("Hello!", "end_turn");

        using var orchestrator = new AgentOrchestrator(claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy());

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Hi", "system"))
        {
            events.Add(evt);
        }

        events.OfType<FinalResponse>().Should().ContainSingle();
        events.OfType<BudgetWarning>().Should().BeEmpty();
        events.OfType<BudgetExhausted>().Should().BeEmpty();
    }

    // -------------------------------------------------------------------------
    // ToolCalls budget
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_YieldBudgetExhausted_WhenToolCallLimitReached()
    {
        // Two tool calls arrive in a single Claude response with MaxToolCalls=1.
        // The first call consumes the entire ToolCalls budget (0→1=limit).
        // The second call must be pre-blocked, emitting BudgetExhausted.
        var claudeClient = new BudgetMockClaudeClient();

        claudeClient.AddToolCallStarted("read_file", "tc_1", "{\"path\":\"file.txt\"}");
        claudeClient.AddToolCallStarted("read_file", "tc_2", "{\"path\":\"file2.txt\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 1);
        var tracker = new TaskBudgetTracker(budget);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Do something", "system"))
        {
            events.Add(evt);
        }

        // The second tool call should be blocked by BudgetExhausted
        events.OfType<BudgetExhausted>().Should()
            .Contain(e => e.Dimension == BudgetDimension.ToolCalls,
                "second tool call must be pre-blocked when MaxToolCalls=1 budget is exhausted");
    }

    [Fact]
    public async Task RunAsync_Should_YieldBudgetWarning_WhenToolCallsAt80Percent()
    {
        // Budget: 5 tool calls (80% = 4). We'll make 4 calls.
        var claudeClient = new BudgetMockClaudeClient();

        // 4 sequential tool calls
        for (int i = 1; i <= 4; i++)
        {
            claudeClient.AddToolCallStarted("read_file", $"tc_{i}", "{\"path\":\"f.txt\"}");
            claudeClient.AddFinalResponse("", "tool_use");
        }

        claudeClient.AddFinalResponse("All done", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 5);
        var tracker = new TaskBudgetTracker(budget);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Do something", "system"))
        {
            events.Add(evt);
        }

        // After 4/5 calls (80%), a BudgetWarning should be emitted for ToolCalls
        events.OfType<BudgetWarning>()
            .Should().Contain(e => e.Dimension == BudgetDimension.ToolCalls,
                "80% of ToolCalls budget should trigger a warning");
    }

    [Fact]
    public async Task RunAsync_Should_EmitBudgetWarningOnce_PerDimension()
    {
        // Budget: 5 tool calls. Make 5 calls — warning should fire once at 4/5 (80%)
        var claudeClient = new BudgetMockClaudeClient();
        for (int i = 1; i <= 5; i++)
        {
            claudeClient.AddToolCallStarted("read_file", $"tc_{i}", "{\"path\":\"f.txt\"}");
            claudeClient.AddFinalResponse("", "tool_use");
        }

        claudeClient.AddFinalResponse("Done", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 5);
        var tracker = new TaskBudgetTracker(budget);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Do something", "system"))
        {
            events.Add(evt);
        }

        events.OfType<BudgetWarning>()
            .Where(e => e.Dimension == BudgetDimension.ToolCalls)
            .Should().HaveCount(1, "BudgetWarning should be emitted at most once per dimension");
    }

    // -------------------------------------------------------------------------
    // FilesModified budget
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_ConsumesFilesModified_WhenWriteFileTool()
    {
        var claudeClient = new BudgetMockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "tc_wf", "{\"path\":\"f.txt\",\"content\":\"x\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Written", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 10, MaxFilesModified: 1);
        var tracker = new TaskBudgetTracker(budget);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Write file", "system"))
        {
            events.Add(evt);
        }

        // After one successful write_file, the FilesModified counter should be 1
        var snapshot = tracker.GetSnapshot();
        snapshot.FilesModified.Should().Be(1);
    }

    // -------------------------------------------------------------------------
    // ProcessesSpawned budget
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_ConsumesProcessesSpawned_WhenRunCommandTool()
    {
        var claudeClient = new BudgetMockClaudeClient();
        claudeClient.AddToolCallStarted("run_command", "tc_rc", "{\"executable\":\"echo\",\"arguments\":[\"hi\"]}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Command done", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 10, MaxProcessesSpawned: 1);
        var tracker = new TaskBudgetTracker(budget);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Run command", "system"))
        {
            events.Add(evt);
        }

        var snapshot = tracker.GetSnapshot();
        snapshot.ProcessesSpawned.Should().Be(1);
    }

    // -------------------------------------------------------------------------
    // BudgetWarning event properties
    // -------------------------------------------------------------------------

    [Fact]
    public void BudgetWarning_Should_HaveCorrectProperties()
    {
        var evt = new BudgetWarning(BudgetDimension.ToolCalls, 0.85);
        evt.Dimension.Should().Be(BudgetDimension.ToolCalls);
        evt.Percentage.Should().BeApproximately(0.85, 1e-9);
        evt.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1));
    }

    // -------------------------------------------------------------------------
    // BudgetExhausted event properties
    // -------------------------------------------------------------------------

    [Fact]
    public void BudgetExhausted_Should_HaveCorrectProperties()
    {
        var evt = new BudgetExhausted(BudgetDimension.Tokens);
        evt.Dimension.Should().Be(BudgetDimension.Tokens);
        evt.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1));
    }

    // -------------------------------------------------------------------------
    // FinalResponse with token counts
    // -------------------------------------------------------------------------

    [Fact]
    public void FinalResponse_Should_HaveDefaultZeroTokens_WhenNotProvided()
    {
        var evt = new FinalResponse("content", "end_turn");
        evt.InputTokens.Should().Be(0);
        evt.OutputTokens.Should().Be(0);
    }

    [Fact]
    public void FinalResponse_Should_AcceptTokenCounts()
    {
        var evt = new FinalResponse("content", "end_turn", InputTokens: 500, OutputTokens: 200);
        evt.InputTokens.Should().Be(500);
        evt.OutputTokens.Should().Be(200);
    }

    // -------------------------------------------------------------------------
    // Fix 1: Outer loop must stop on budget exhaustion even without state manager
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_StopLoop_WhenToolCallBudgetExhausted_WithNoStateManager()
    {
        // Verifies the outer agentic loop terminates on budget exhaustion even when
        // _stateManager is null (normal session wiring via SessionFactory).
        // After the first tool call consumes MaxToolCalls=1, IsExhausted=true and the
        // top-of-loop guard must prevent a second Claude API call.
        int claudeCallCount = 0;
        var claudeClient = new CountingMockClaudeClient(callIdx =>
        {
            claudeCallCount = callIdx + 1;
            return callIdx switch
            {
                // First call: one tool use that consumes the entire ToolCalls budget
                0 => [new ToolCallStarted("read_file", "tc_1", "{\"path\":\"f.txt\"}"), new FinalResponse("", "tool_use")],
                // Second call must NOT happen — budget is exhausted
                _ => [new FinalResponse("Should not reach here", "end_turn")]
            };
        });

        var budget = new TaskBudget(MaxToolCalls: 1);
        var tracker = new TaskBudgetTracker(budget);

        // Deliberately do NOT pass a stateManager — this is the normal wiring path
        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        await foreach (var _ in orchestrator.RunAsync("Do something", "system"))
        {
            // consume all events
        }

        // After the first tool call consumes 1/1 of the ToolCalls budget, IsExhausted
        // becomes true and the top-of-loop guard must prevent a second Claude API call.
        claudeCallCount.Should().Be(1,
            "the outer loop must not make a second Claude API call after ToolCalls budget is exhausted");
    }

    // -------------------------------------------------------------------------
    // Fix 2: No extra side-effect past FilesModified/ProcessesSpawned cap
    // -------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_Should_BlockWriteFile_WhenFilesModifiedBudgetAlreadyExhausted()
    {
        // Two write_file calls arrive in one Claude response with MaxFilesModified=1.
        // The first call pre-consumes the full FilesModified budget (0→1=limit).
        // The second call must be pre-blocked — the side effect must NOT occur.
        var executedTools = new List<string>();
        var claudeClient = new BudgetMockClaudeClient();

        // Both tool calls in a single Claude response
        claudeClient.AddToolCallStarted("write_file", "tc_wf1", "{\"path\":\"f1.txt\",\"content\":\"a\"}");
        claudeClient.AddToolCallStarted("write_file", "tc_wf2", "{\"path\":\"f2.txt\",\"content\":\"b\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        // MaxFilesModified=1: first write_file exhausts the budget; second must be blocked
        var budget = new TaskBudget(MaxToolCalls: 10, MaxFilesModified: 1);
        var tracker = new TaskBudgetTracker(budget);
        var trackingRegistry = new TrackingToolRegistry(executedTools);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, trackingRegistry, new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Write files", "system"))
        {
            events.Add(evt);
        }

        // First write_file executed; second was pre-blocked before any side-effect
        executedTools.Should().HaveCount(1, "only the first write_file may execute when MaxFilesModified=1");

        // BudgetExhausted must be emitted for the FilesModified dimension
        events.OfType<BudgetExhausted>().Should()
            .Contain(e => e.Dimension == BudgetDimension.FilesModified,
                "BudgetExhausted must be emitted for FilesModified when cap is reached");
    }

    [Fact]
    public async Task RunAsync_Should_BlockRunCommand_WhenProcessesSpawnedBudgetAlreadyExhausted()
    {
        // Two run_command calls arrive in one Claude response with MaxProcessesSpawned=1.
        // The first call pre-consumes the full ProcessesSpawned budget.
        // The second call must be pre-blocked — no extra spawn occurs.
        var executedTools = new List<string>();
        var claudeClient = new BudgetMockClaudeClient();

        claudeClient.AddToolCallStarted("run_command", "tc_rc1", "{\"executable\":\"echo\",\"arguments\":[\"1\"]}");
        claudeClient.AddToolCallStarted("run_command", "tc_rc2", "{\"executable\":\"echo\",\"arguments\":[\"2\"]}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Done", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 10, MaxProcessesSpawned: 1);
        var tracker = new TaskBudgetTracker(budget);
        var trackingRegistry = new TrackingToolRegistry(executedTools);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, trackingRegistry, new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Run cmds", "system"))
        {
            events.Add(evt);
        }

        executedTools.Should().HaveCount(1, "only the first run_command may execute when MaxProcessesSpawned=1");
        events.OfType<BudgetExhausted>().Should()
            .Contain(e => e.Dimension == BudgetDimension.ProcessesSpawned,
                "BudgetExhausted must be emitted for ProcessesSpawned when cap is reached");
    }

    [Fact]
    public async Task RunAsync_Should_ConsumesFilesModified_PreExecution_WhenWriteFileTool()
    {
        // After a successful write_file, the FilesModified counter should be 1 (consumed pre-execution)
        var claudeClient = new BudgetMockClaudeClient();
        claudeClient.AddToolCallStarted("write_file", "tc_wf", "{\"path\":\"f.txt\",\"content\":\"x\"}");
        claudeClient.AddFinalResponse("", "tool_use");
        claudeClient.AddFinalResponse("Written", "end_turn");

        var budget = new TaskBudget(MaxToolCalls: 10, MaxFilesModified: 5);
        var tracker = new TaskBudgetTracker(budget);

        using var orchestrator = new AgentOrchestrator(
            claudeClient, new BudgetMockToolRegistry(), new BudgetMockSecurityPolicy(),
            budgetTracker: tracker);

        await foreach (var _ in orchestrator.RunAsync("Write file", "system"))
        {
            // consume all events
        }

        tracker.GetSnapshot().FilesModified.Should().Be(1,
            "FilesModified should be consumed (pre-execution) after a successful write_file");
    }

    private sealed class BudgetMockClaudeClient : IClaudeClient
    {
        private readonly List<List<AgentEvent>> _batches = [];
        private int _callIndex;

        public void AddToolCallStarted(string name, string id, string input)
        {
            EnsureBatch();
            _batches[^1].Add(new ToolCallStarted(name, id, input));
        }

        public void AddFinalResponse(string content, string stopReason)
        {
            EnsureBatch();
            _batches[^1].Add(new FinalResponse(content, stopReason));
            _batches.Add([]);
        }

        private void EnsureBatch()
        {
            if (_batches.Count == 0)
            {
                _batches.Add([]);
            }
        }

        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            if (_callIndex < _batches.Count)
            {
                foreach (var evt in _batches[_callIndex++])
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

    private sealed class BudgetMockToolRegistry : IToolRegistry
    {
        public void Register(ITool tool) { }
        public object GetToolDefinitions() => Array.Empty<object>();

        public Task<string> ExecuteAsync(string name, JsonElement input, CancellationToken cancellationToken)
            => Task.FromResult("tool result");
    }

    private sealed class BudgetMockSecurityPolicy : ISecurityPolicy
    {
        public bool IsApprovalRequired(string toolName) => false;

        public string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null)
            => path;

        public void ValidateCommand(string executable, IEnumerable<string> arguments, CorrelationContext? correlationContext = null) { }

        public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
            => new Dictionary<string, string?>(environment);
    }

    private sealed class CountingMockClaudeClient : IClaudeClient
    {
        private readonly Func<int, IEnumerable<AgentEvent>> _onCall;
        private int _callIndex;

        public CountingMockClaudeClient(Func<int, IEnumerable<AgentEvent>> onCall) => _onCall = onCall;

        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            foreach (var evt in _onCall(_callIndex++))
            {
                yield return evt;
            }
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken = default)
            => Task.FromResult(100);
    }

    private sealed class TrackingToolRegistry : IToolRegistry
    {
        private readonly List<string> _executedTools;

        public TrackingToolRegistry(List<string> executedTools) => _executedTools = executedTools;

        public void Register(ITool tool) { }
        public object GetToolDefinitions() => Array.Empty<object>();

        public Task<string> ExecuteAsync(string name, JsonElement input, CancellationToken cancellationToken)
        {
            _executedTools.Add(name);
            return Task.FromResult("tool result");
        }
    }
}
