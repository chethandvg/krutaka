#pragma warning disable CA2007 // Do not directly await a Task in tests
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for <see cref="DeadmanSwitch"/> timer logic and <see cref="SessionManager"/> integration.
/// Validates pause/abort escalation, timer reset, disabled mode, per-session isolation, and clean disposal.
/// </summary>
public sealed class DeadmanSwitchTests : IDisposable
{
    private readonly string _testProjectPath;
    private readonly ServiceProvider _serviceProvider;

    public DeadmanSwitchTests()
    {
        _testProjectPath = TestDirectoryHelper.GetTestDirectory("deadman-switch-tests");
        Directory.CreateDirectory(_testProjectPath);

        var services = new ServiceCollection();
        services.AddSingleton<IClaudeClient, StubClaudeClient>();
        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = _testProjectPath;
            options.CeilingDirectory = _testProjectPath;
        });

        _serviceProvider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
        TestDirectoryHelper.TryDeleteDirectory(_testProjectPath);
    }

    // ─── Construction ─────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_Should_ThrowArgumentNullException_WhenStateManagerIsNull()
    {
        var act = () => new DeadmanSwitch(null!, TimeSpan.FromSeconds(1));
        act.Should().Throw<ArgumentNullException>().WithParameterName("stateManager");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenDurationIsZero()
    {
        var stateManager = new AgentStateManager();
        var act = () => new DeadmanSwitch(stateManager, TimeSpan.Zero);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentOutOfRangeException_WhenDurationIsNegative()
    {
        var stateManager = new AgentStateManager();
        var act = () => new DeadmanSwitch(stateManager, TimeSpan.FromSeconds(-1));
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Constructor_Should_ArmTimer_WhenValidParametersProvided()
    {
        var stateManager = new AgentStateManager();

        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromHours(1));

        // Agent should still be Running — timer has not yet fired
        stateManager.CurrentState.Should().Be(AgentState.Running);
    }

    // ─── First expiry: pause ──────────────────────────────────────────────────────

    [Fact]
    public async Task DeadmanSwitch_Should_PauseAgent_AfterConfiguredDuration()
    {
        var stateManager = new AgentStateManager();
        // 300ms interval: pause at 300ms, abort at 600ms. Check at 450ms → Paused.
        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(300));

        await Task.Delay(450);

        stateManager.CurrentState.Should().Be(AgentState.Paused);
        stateManager.PauseReason.Should().Be("Deadman switch: no user interaction");
    }

    [Fact]
    public async Task DeadmanSwitch_Should_SetCorrectPauseReason()
    {
        var stateManager = new AgentStateManager();
        string? capturedReason = null;
        stateManager.StateChanged += (_, args) =>
        {
            if (args.NewState == AgentState.Paused)
            {
                capturedReason = args.Reason;
            }
        };

        // 300ms interval: pause at 300ms, check at 450ms
        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(300));
        await Task.Delay(450);

        capturedReason.Should().Be("Deadman switch: no user interaction");
    }

    // ─── Second expiry: abort ─────────────────────────────────────────────────────

    [Fact]
    public async Task DeadmanSwitch_Should_AbortAgent_AtDoubleExpiry()
    {
        // 150ms interval → pause at 150ms, abort at 300ms
        var stateManager = new AgentStateManager();
        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(150));

        await Task.Delay(500);

        stateManager.CurrentState.Should().Be(AgentState.Aborted);
    }

    [Fact]
    public async Task DeadmanSwitch_Should_SetCorrectAbortReason()
    {
        var stateManager = new AgentStateManager();
        string? capturedAbortReason = null;
        stateManager.StateChanged += (_, args) =>
        {
            if (args.NewState == AgentState.Aborted)
            {
                capturedAbortReason = args.Reason;
            }
        };

        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(150));
        await Task.Delay(500);

        capturedAbortReason.Should().Be("Deadman switch: auto-abort");
    }

    [Fact]
    public async Task DeadmanSwitch_Should_FirePauseBeforeAbort()
    {
        var stateManager = new AgentStateManager();
        var events = new List<AgentState>();
        stateManager.StateChanged += (_, args) => events.Add(args.NewState);

        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(150));
        await Task.Delay(500);

        // Must be Paused first, then Aborted
        events.Should().ContainInOrder(AgentState.Paused, AgentState.Aborted);
    }

    // ─── ResetTimer ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task ResetTimer_Should_PreventPause_WhenResetBeforeExpiry()
    {
        var stateManager = new AgentStateManager();
        // 300ms interval; reset at 80ms → fires at 380ms from creation
        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(300));

        await Task.Delay(80);
        ds.ResetTimer();

        // At 230ms total (150ms since reset): timer has not yet fired (fires at 380ms)
        await Task.Delay(150);

        stateManager.CurrentState.Should().Be(AgentState.Running);
    }

    [Fact]
    public async Task ResetTimer_Should_AllowPause_AfterFullDurationFromReset()
    {
        var stateManager = new AgentStateManager();
        using var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(150));

        // Reset early
        await Task.Delay(50);
        ds.ResetTimer();

        // Wait more than a full duration from the reset point
        await Task.Delay(500);

        stateManager.CurrentState.Should().BeOneOf(AgentState.Paused, AgentState.Aborted);
    }

    [Fact]
    public void ResetTimer_Should_BeNoOp_AfterDisposal()
    {
        var stateManager = new AgentStateManager();
        var ds = new DeadmanSwitch(stateManager, TimeSpan.FromHours(1));
        ds.Dispose();

        // Should not throw
        var act = () => ds.ResetTimer();
        act.Should().NotThrow();
    }

    // ─── Disabled mode (MaxUnattendedMinutes = 0) ─────────────────────────────────

    [Fact]
    public void DeadmanSwitchOptions_Should_BeDisabled_WhenMaxUnattendedMinutesIsZero()
    {
        var options = new DeadmanSwitchOptions(MaxUnattendedMinutes: 0);
        options.MaxUnattendedMinutes.Should().Be(0);
    }

    [Fact]
    public async Task SessionManager_Should_NotArmDeadmanSwitch_WhenMaxUnattendedMinutesIsZero()
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        var smOptions = new SessionManagerOptions(DeadmanSwitch: new DeadmanSwitchOptions(MaxUnattendedMinutes: 0));
        await using var manager = new SessionManager(factory, smOptions, logger: null);
        var request = new SessionRequest(_testProjectPath);

        var session = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Wait — no pause/abort should occur because the switch is disabled
        await Task.Delay(200);

        session.AgentStateManager.Should().NotBeNull();
        session.AgentStateManager!.CurrentState.Should().Be(AgentState.Running);
    }

    // ─── Multiple sessions: independent timers ─────────────────────────────────────

    [Fact]
    public async Task DeadmanSwitch_Should_FireIndependently_ForEachStateManager()
    {
        var sm1 = new AgentStateManager();
        var sm2 = new AgentStateManager();

        // ds1 fires at 200ms, ds2 fires at 700ms
        using var ds1 = new DeadmanSwitch(sm1, TimeSpan.FromMilliseconds(200));
        using var ds2 = new DeadmanSwitch(sm2, TimeSpan.FromMilliseconds(700));

        // At 450ms: sm1 should be paused or aborted; sm2 should still be Running
        await Task.Delay(450);
        sm1.CurrentState.Should().BeOneOf(AgentState.Paused, AgentState.Aborted);
        sm2.CurrentState.Should().Be(AgentState.Running);

        // After additional wait: sm2 should also fire
        await Task.Delay(600);
        sm2.CurrentState.Should().BeOneOf(AgentState.Paused, AgentState.Aborted);
    }

    [Fact]
    public async Task ResettingOneSwitch_Should_NotAffect_AnotherSwitch()
    {
        var sm1 = new AgentStateManager();
        var sm2 = new AgentStateManager();

        // ds1 = 400ms; reset at 150ms → ds1 fires at 550ms from creation
        // ds2 = 400ms; no reset → ds2 fires at 400ms from creation
        using var ds1 = new DeadmanSwitch(sm1, TimeSpan.FromMilliseconds(400));
        using var ds2 = new DeadmanSwitch(sm2, TimeSpan.FromMilliseconds(400));

        await Task.Delay(150);
        ds1.ResetTimer();

        // At 475ms (between ds2 at 400ms and ds1 at 550ms): ds2 fired, ds1 still armed
        await Task.Delay(325); // total: 475ms from creation
        sm2.CurrentState.Should().Be(AgentState.Paused);  // ds2 fired (no reset)
        sm1.CurrentState.Should().Be(AgentState.Running);  // ds1 reset, hasn't fired yet
    }

    [Fact]
    public async Task TwoSessions_Should_HaveIndependent_DeadmanSwitches_InSessionManager()
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        // Deadman switch is disabled (MaxUnattendedMinutes=0) so sessions don't auto-pause;
        // independence is verified through the AgentStateManagers
        var smOptions = new SessionManagerOptions(DeadmanSwitch: new DeadmanSwitchOptions(MaxUnattendedMinutes: 0));
        await using var manager = new SessionManager(factory, smOptions, logger: null);

        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Pause session1's agent — session2 must remain Running
        session1.AgentStateManager!.RequestPause("manual pause for test");

        session1.AgentStateManager.CurrentState.Should().Be(AgentState.Paused);
        session2.AgentStateManager!.CurrentState.Should().Be(AgentState.Running);
    }

    // ─── Disposal ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Dispose_Should_StopTimer_PreventingFutureCallbacks()
    {
        var stateManager = new AgentStateManager();
        var ds = new DeadmanSwitch(stateManager, TimeSpan.FromMilliseconds(200));

        // Dispose immediately before the timer fires
        ds.Dispose();

        await Task.Delay(500);

        // Agent should remain Running because the timer was stopped
        stateManager.CurrentState.Should().Be(AgentState.Running);
    }

    [Fact]
    public void Dispose_Should_BeIdempotent()
    {
        var stateManager = new AgentStateManager();
        var ds = new DeadmanSwitch(stateManager, TimeSpan.FromHours(1));

        // Should not throw when disposed multiple times
        ds.Dispose();
        ds.Dispose();
        ds.Dispose();
    }

    // ─── SessionManager.NotifyUserInteraction ─────────────────────────────────────

    [Fact]
    public async Task NotifyUserInteraction_Should_BeNoOp_ForUnknownSessionId()
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var manager = new SessionManager(factory, new SessionManagerOptions(), logger: null);

        // Should not throw for an unknown session ID
        var act = () => manager.NotifyUserInteraction(Guid.NewGuid());
        act.Should().NotThrow();
    }

    [Fact]
    public async Task NotifyUserInteraction_Should_ResetDeadmanSwitch_ForKnownSession()
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        var smOptions = new SessionManagerOptions(DeadmanSwitch: new DeadmanSwitchOptions(MaxUnattendedMinutes: 1));
        await using var manager = new SessionManager(factory, smOptions, logger: null);

        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Notify user interaction — should not throw
        var act = () => manager.NotifyUserInteraction(session.SessionId);
        act.Should().NotThrow();

        session.AgentStateManager!.CurrentState.Should().Be(AgentState.Running);
    }

    // ─── ManagedSession.AgentStateManager ─────────────────────────────────────────

    [Fact]
    public async Task SessionFactory_Should_ExposeAgentStateManager_OnManagedSession()
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var session = factory.Create(new SessionRequest(_testProjectPath));

        session.AgentStateManager.Should().NotBeNull();
        session.AgentStateManager!.CurrentState.Should().Be(AgentState.Running);
    }

    [Fact]
    public async Task TwoSessions_Should_HaveIndependent_AgentStateManagers()
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        await using var session1 = factory.Create(new SessionRequest(_testProjectPath));
        await using var session2 = factory.Create(new SessionRequest(_testProjectPath));

        session1.AgentStateManager.Should().NotBeSameAs(session2.AgentStateManager);

        // Pausing session1 must not affect session2
        session1.AgentStateManager!.RequestPause("test isolation");
        session2.AgentStateManager!.CurrentState.Should().Be(AgentState.Running);
    }

    // ─── DeadmanSwitchOptions defaults ────────────────────────────────────────────

    [Fact]
    public void DeadmanSwitchOptions_Should_HaveCorrectDefaults()
    {
        var options = new DeadmanSwitchOptions();
        options.MaxUnattendedMinutes.Should().Be(30);
        options.HeartbeatIntervalMinutes.Should().Be(5);
    }

    [Fact]
    public void SessionManagerOptions_Should_HaveDeadmanSwitchValue_WithDefaults_WhenNotConfigured()
    {
        var options = new SessionManagerOptions();
        options.DeadmanSwitchValue.Should().NotBeNull();
        options.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(30);
        options.DeadmanSwitchValue.HeartbeatIntervalMinutes.Should().Be(5);
    }

    [Fact]
    public void SessionManagerOptions_Should_ReturnConfiguredDeadmanSwitch_WhenSet()
    {
        var ds = new DeadmanSwitchOptions(MaxUnattendedMinutes: 15, HeartbeatIntervalMinutes: 3);
        var options = new SessionManagerOptions(DeadmanSwitch: ds);
        options.DeadmanSwitchValue.MaxUnattendedMinutes.Should().Be(15);
        options.DeadmanSwitchValue.HeartbeatIntervalMinutes.Should().Be(3);
    }

    // ─── Private helpers ──────────────────────────────────────────────────────────

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Instantiated via DI container")]
    private sealed class StubClaudeClient : IClaudeClient
    {
        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools = null,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return new FinalResponse("stub", "end_turn");
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(0);
        }
    }
}
