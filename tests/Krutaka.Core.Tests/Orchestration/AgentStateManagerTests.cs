#pragma warning disable CA2007 // Do not directly await a Task in tests
using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for <see cref="AgentStateManager"/> state machine logic.
/// </summary>
public sealed class AgentStateManagerTests
{
    // ─── Initial state ──────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_Should_StartInRunningState()
    {
        var manager = new AgentStateManager();
        manager.CurrentState.Should().Be(AgentState.Running);
        manager.PauseReason.Should().BeNull();
    }

    // ─── Valid transitions ───────────────────────────────────────────────────────

    [Fact]
    public void RequestPause_Should_TransitionToPaused_WhenRunning()
    {
        var manager = new AgentStateManager();

        manager.RequestPause("test reason");

        manager.CurrentState.Should().Be(AgentState.Paused);
        manager.PauseReason.Should().Be("test reason");
    }

    [Fact]
    public void ResumeAgent_Should_TransitionToRunning_WhenPaused()
    {
        var manager = new AgentStateManager();
        manager.RequestPause("pausing");
        // Allow debounce to pass
        Thread.Sleep(1100);

        manager.ResumeAgent();

        manager.CurrentState.Should().Be(AgentState.Running);
        manager.PauseReason.Should().BeNull();
    }

    [Fact]
    public void RequestAbort_Should_TransitionToAborted_WhenRunning()
    {
        var manager = new AgentStateManager();

        manager.RequestAbort("abort reason");

        manager.CurrentState.Should().Be(AgentState.Aborted);
        manager.PauseReason.Should().BeNull();
    }

    [Fact]
    public void RequestAbort_Should_TransitionToAborted_WhenPaused()
    {
        var manager = new AgentStateManager();
        manager.RequestPause("pausing");
        Thread.Sleep(1100);

        manager.RequestAbort("abort from paused");

        manager.CurrentState.Should().Be(AgentState.Aborted);
    }

    [Fact]
    public void TryTransition_Should_ReturnTrue_ForRunningToPaused()
    {
        var manager = new AgentStateManager();

        var result = manager.TryTransition(AgentState.Paused);

        result.Should().BeTrue();
        manager.CurrentState.Should().Be(AgentState.Paused);
    }

    [Fact]
    public void TryTransition_Should_ReturnTrue_ForPausedToRunning()
    {
        var manager = new AgentStateManager();
        manager.TryTransition(AgentState.Paused);
        Thread.Sleep(1100);

        var result = manager.TryTransition(AgentState.Running);

        result.Should().BeTrue();
        manager.CurrentState.Should().Be(AgentState.Running);
    }

    [Fact]
    public void TryTransition_Should_ReturnTrue_ForRunningToAborted()
    {
        var manager = new AgentStateManager();

        var result = manager.TryTransition(AgentState.Aborted);

        result.Should().BeTrue();
        manager.CurrentState.Should().Be(AgentState.Aborted);
    }

    [Fact]
    public void TryTransition_Should_ReturnTrue_ForPausedToAborted()
    {
        var manager = new AgentStateManager();
        manager.TryTransition(AgentState.Paused);
        Thread.Sleep(1100);

        var result = manager.TryTransition(AgentState.Aborted);

        result.Should().BeTrue();
        manager.CurrentState.Should().Be(AgentState.Aborted);
    }

    // ─── Invalid transitions ─────────────────────────────────────────────────────

    [Fact]
    public void TryTransition_Should_ReturnFalse_ForAbortedToRunning()
    {
        var manager = new AgentStateManager();
        manager.RequestAbort("abort");

        var result = manager.TryTransition(AgentState.Running);

        result.Should().BeFalse();
        manager.CurrentState.Should().Be(AgentState.Aborted);
    }

    [Fact]
    public void TryTransition_Should_ReturnFalse_ForAbortedToPaused()
    {
        var manager = new AgentStateManager();
        manager.RequestAbort("abort");

        var result = manager.TryTransition(AgentState.Paused);

        result.Should().BeFalse();
        manager.CurrentState.Should().Be(AgentState.Aborted);
    }

    [Fact]
    public void TryTransition_Should_ReturnFalse_ForRunningToRunning()
    {
        var manager = new AgentStateManager();

        var result = manager.TryTransition(AgentState.Running);

        result.Should().BeFalse();
        manager.CurrentState.Should().Be(AgentState.Running);
    }

    [Fact]
    public void RequestAbort_Should_BeNoOp_WhenAlreadyAborted()
    {
        var manager = new AgentStateManager();
        manager.RequestAbort("first");

        // Should not throw
        manager.RequestAbort("second");

        manager.CurrentState.Should().Be(AgentState.Aborted);
    }

    [Fact]
    public void ResumeAgent_Should_BeNoOp_WhenNotPaused()
    {
        var manager = new AgentStateManager();

        // Should not throw when called from Running state
        manager.ResumeAgent();

        manager.CurrentState.Should().Be(AgentState.Running);
    }

    // ─── Debounce ────────────────────────────────────────────────────────────────

    [Fact]
    public void TryTransition_Should_ReturnFalse_WhenDebouncePeriodNotElapsed()
    {
        var manager = new AgentStateManager();
        // Transition once (no debounce needed from initial state which has MinValue timestamp)
        manager.TryTransition(AgentState.Paused).Should().BeTrue();

        // Immediately try to transition again — debounce should block it
        var result = manager.TryTransition(AgentState.Running);

        result.Should().BeFalse();
        manager.CurrentState.Should().Be(AgentState.Paused);
    }

    // ─── StateChanged event ──────────────────────────────────────────────────────

    [Fact]
    public void StateChanged_Should_BeFired_OnSuccessfulTransition()
    {
        var manager = new AgentStateManager();
        AgentStateChangedEventArgs? capturedArgs = null;
        manager.StateChanged += (_, args) => capturedArgs = args;

        manager.RequestPause("testing events");

        capturedArgs.Should().NotBeNull();
        capturedArgs!.OldState.Should().Be(AgentState.Running);
        capturedArgs.NewState.Should().Be(AgentState.Paused);
        capturedArgs.Reason.Should().Be("testing events");
    }

    [Fact]
    public void StateChanged_Should_NotBeFired_OnInvalidTransition()
    {
        var manager = new AgentStateManager();
        manager.RequestAbort("abort");
        var eventCount = 0;
        manager.StateChanged += (_, _) => eventCount++;

        // Invalid transition — Aborted → Running
        manager.TryTransition(AgentState.Running);

        eventCount.Should().Be(0);
    }

    // ─── Thread safety ───────────────────────────────────────────────────────────

    [Fact]
    public void RequestAbort_Should_BeThreadSafe_WhenCalledConcurrently()
    {
        var manager = new AgentStateManager();
        var eventCount = 0;
        manager.StateChanged += (_, _) => Interlocked.Increment(ref eventCount);

        // Fire RequestAbort from many threads simultaneously
        Parallel.For(0, 20, _ => manager.RequestAbort("concurrent abort"));

        // Only one transition should succeed (Running → Aborted)
        manager.CurrentState.Should().Be(AgentState.Aborted);
        eventCount.Should().Be(1);
    }

    // ─── Orchestrator integration ─────────────────────────────────────────────────

    [Fact]
    public async Task Orchestrator_Should_AcceptNullStateManager()
    {
        // Arrange
        var claudeClient = new MockClaudeClientForStateTests();
        claudeClient.AddFinalResponse("Done", "end_turn");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistryForStateTests(),
            new MockSecurityPolicyForStateTests(),
            stateManager: null);

        // Act — should work fine with no state manager
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Hello", "System"))
        {
            events.Add(evt);
        }

        // Assert
        events.OfType<FinalResponse>().Should().ContainSingle();
    }

    [Fact]
    public async Task Orchestrator_Should_YieldAgentPaused_WhenStateManagerIsPaused()
    {
        // Arrange
        var claudeClient = new MockClaudeClientForStateTests();
        var toolRegistry = new MockToolRegistryForStateTests();
        toolRegistry.AddTool("read_file", "file contents");

        // First response: tool use
        claudeClient.AddToolCallStarted("read_file", "tool_1", "{}");
        claudeClient.AddFinalResponse("", "tool_use");

        // Second response: final answer
        claudeClient.AddFinalResponse("Done", "end_turn");

        var stateManager = new AgentStateManager();
        stateManager.RequestPause("manual pause");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicyForStateTests(),
            stateManager: stateManager);

        // Resume the agent after a short delay to avoid the test hanging
        var resumeTask = Task.Run(async () =>
        {
            await Task.Delay(300);
            await Task.Delay(1100); // ensure debounce elapses
            stateManager.ResumeAgent();
        });

        // Act — run to natural completion
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Hello", "System"))
        {
            events.Add(evt);
        }

        await resumeTask;

        // Assert — should have seen AgentPaused and AgentResumed events
        events.OfType<AgentPaused>().Should().ContainSingle()
            .Which.Reason.Should().Be("manual pause");
        events.OfType<AgentResumed>().Should().ContainSingle();
    }

    [Fact]
    public async Task Orchestrator_Should_ExitLoop_WhenStateManagerIsAborted()
    {
        // Arrange
        var claudeClient = new MockClaudeClientForStateTests();
        var toolRegistry = new MockToolRegistryForStateTests();
        toolRegistry.AddTool("read_file", "file contents");

        // First response: tool use
        claudeClient.AddToolCallStarted("read_file", "tool_1", "{}");
        claudeClient.AddFinalResponse("", "tool_use");

        var stateManager = new AgentStateManager();
        stateManager.RequestAbort("terminate now");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            new MockSecurityPolicyForStateTests(),
            stateManager: stateManager);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Hello", "System"))
        {
            events.Add(evt);
        }

        // Assert — loop should have exited without executing tools or calling Claude
        events.OfType<ToolCallCompleted>().Should().BeEmpty();
        toolRegistry.ExecutedTools.Should().BeEmpty();
        claudeClient.CallCount.Should().Be(0, "abort gate at top of loop must prevent all Claude API calls");
    }

    [Fact]
    public async Task Orchestrator_Should_NotCallClaude_WhenAbortedBeforeFirstTurn()
    {
        // Arrange — agent is aborted BEFORE RunAsync is called
        var claudeClient = new MockClaudeClientForStateTests();
        // No events configured — if Claude is called, _callIndex would increment

        var stateManager = new AgentStateManager();
        stateManager.RequestAbort("pre-emptive abort");

        using var orchestrator = new AgentOrchestrator(
            claudeClient,
            new MockToolRegistryForStateTests(),
            new MockSecurityPolicyForStateTests(),
            stateManager: stateManager);

        // Act
        var events = new List<AgentEvent>();
        await foreach (var evt in orchestrator.RunAsync("Hello", "System"))
        {
            events.Add(evt);
        }

        // Assert — abort gate at top of loop must fire immediately, producing no events
        events.Should().BeEmpty("the abort gate must exit before any Claude API call or event emission");
        claudeClient.CallCount.Should().Be(0, "terminal Aborted state must prevent Claude API calls");
    }

    // ─── AgentState enum ─────────────────────────────────────────────────────────

    [Fact]
    public void AgentState_Should_HaveExpectedValues()
    {
        ((int)AgentState.Running).Should().Be(0);
        ((int)AgentState.Paused).Should().Be(1);
        ((int)AgentState.Aborted).Should().Be(2);
    }

    // ─── AgentEvent records ───────────────────────────────────────────────────────

    [Fact]
    public void AgentPaused_Should_HaveReason()
    {
        var evt = new AgentPaused("some reason");
        evt.Reason.Should().Be("some reason");
        evt.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void AgentResumed_Should_HaveTimestamp()
    {
        var evt = new AgentResumed();
        evt.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(5));
    }

    // ─── Private mock helpers ─────────────────────────────────────────────────────

    private sealed class MockClaudeClientForStateTests : IClaudeClient
    {
        private readonly List<List<AgentEvent>> _batches = [];
        private int _callIndex;

        /// <summary>Gets the number of times <see cref="SendMessageAsync"/> was called.</summary>
        public int CallCount => _callIndex;

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
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
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
        {
            return Task.FromResult(100);
        }
    }

    private sealed class MockToolRegistryForStateTests : IToolRegistry
    {
        private readonly Dictionary<string, string> _tools = [];
        public List<string> ExecutedTools { get; } = [];

        public void AddTool(string name, string result)
        {
            _tools[name] = result;
        }

        public void Register(ITool tool) { }

        public object GetToolDefinitions()
        {
            return Array.Empty<object>();
        }

        public Task<string> ExecuteAsync(string name, System.Text.Json.JsonElement input, CancellationToken cancellationToken)
        {
            ExecutedTools.Add(name);
            return Task.FromResult(_tools.TryGetValue(name, out var result) ? result : "ok");
        }
    }

    private sealed class MockSecurityPolicyForStateTests : ISecurityPolicy
    {
        public bool IsApprovalRequired(string toolName) => false;

        public string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null) => path;

        public void ValidateCommand(string executable, IEnumerable<string> arguments, CorrelationContext? correlationContext = null) { }

        public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
        {
            return new Dictionary<string, string?>(environment);
        }
    }
}
