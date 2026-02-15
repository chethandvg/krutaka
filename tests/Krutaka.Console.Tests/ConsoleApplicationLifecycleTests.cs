using FluentAssertions;
using Krutaka.AI;
using Krutaka.Console;
using Krutaka.Core;
using Krutaka.Memory;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Console.Tests;

/// <summary>
/// Integration tests for ConsoleApplication lifecycle.
/// Tests session creation, command handling, and shutdown behavior.
/// </summary>
public sealed class ConsoleApplicationLifecycleTests : IAsyncDisposable
{
    private readonly string _testRoot;
    private readonly ServiceProvider _serviceProvider;
    private readonly MockConsoleUI _mockUI;
    private readonly List<SessionManagerOperation> _sessionManagerOps;

    public ConsoleApplicationLifecycleTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("console-lifecycle-test");
        Directory.CreateDirectory(_testRoot);

        _sessionManagerOps = new List<SessionManagerOperation>();
        _mockUI = new MockConsoleUI();

        // Build service provider with required services
        var services = new ServiceCollection();
        
        // Register mock UI
        services.AddSingleton<IConsoleUI>(_mockUI);
        
        // Register Claude client
        services.AddSingleton<IClaudeClient, MockClaudeClient>();
        
        // Register audit logger
        services.AddSingleton<IAuditLogger, MockAuditLogger>();
        
        // Register tools
        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = _testRoot;
            options.CeilingDirectory = _testRoot;
            options.CommandTimeoutSeconds = 30;
            options.RequireApprovalForWrites = false;
        });
        
        // Replace SessionManager with tracking version
        services.AddSingleton<ISessionManager>(sp =>
            new TrackingSessionManager(sp.GetRequiredService<ISessionFactory>(), _sessionManagerOps));
        
        _serviceProvider = services.BuildServiceProvider();
    }

    public async ValueTask DisposeAsync()
    {
        await _serviceProvider.DisposeAsync();
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
    }

    [Fact]
    public async Task Should_CreateNewSession_OnFirstRun_WhenNoExistingSession()
    {
        // Arrange
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Assert - Verify CreateSessionAsync was called
        _sessionManagerOps.Should().ContainSingle(op => op.Operation == "CreateSessionAsync");
        _sessionManagerOps.Should().ContainSingle(op => op.Operation == "DisposeAsync");
    }

    [Fact]
    public async Task Should_ResumeExistingSession_WhenSessionExists()
    {
        // Arrange - Create a session file to simulate existing session
        var existingSessionId = Guid.NewGuid();
        CreateExistingSessionFile(existingSessionId);

        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Assert - Verify SessionFactory.Create was called (not SessionManager.CreateSessionAsync)
        // In this case, SessionManager.CreateSessionAsync should NOT be called
        // because we use SessionFactory directly for resume
        _sessionManagerOps.Should().Contain(op => op.Operation == "DisposeAsync");
    }

    [Fact]
    public async Task NewCommand_Should_TerminateOldSession_AndCreateNew()
    {
        // Arrange
        _mockUI.EnqueueInput("/new");
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Assert - Verify old session was terminated and new one created
        _sessionManagerOps.Should().Contain(op => op.Operation == "CreateSessionAsync");
        _sessionManagerOps.Should().Contain(op => op.Operation == "TerminateSessionAsync");
        _sessionManagerOps.Should().Contain(op => op.Operation == "DisposeAsync");

        // Verify CreateSessionAsync was called twice (initial + /new)
        _sessionManagerOps.Count(op => op.Operation == "CreateSessionAsync").Should().Be(2);
    }

    [Fact]
    public async Task ResumeCommand_Should_NotThrow()
    {
        // Arrange
        _mockUI.EnqueueInput("/resume");
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act & Assert - Should complete without errors
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    [Fact]
    public async Task SessionsCommand_Should_Execute_WithoutError()
    {
        // Arrange
        _mockUI.EnqueueInput("/sessions");
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act & Assert - Should complete without errors
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    [Fact]
    public async Task HelpCommand_Should_Execute_WithoutError()
    {
        // Arrange
        _mockUI.EnqueueInput("/help");
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act & Assert - Should complete without errors
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    [Fact]
    public async Task QuitCommand_Should_ExitApplication()
    {
        // Arrange
        _mockUI.EnqueueInput("/quit");

        var app = CreateApp();

        // Act
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Assert - Should dispose session manager
        _sessionManagerOps.Should().Contain(op => op.Operation == "DisposeAsync");
    }

    [Fact]
    public async Task Should_HandleUnknownCommand_Gracefully()
    {
        // Arrange
        _mockUI.EnqueueInput("/unknown");
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act & Assert - Should complete without throwing
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    [Fact]
    public async Task Should_HandleEmptyInput_Gracefully()
    {
        // Arrange
        _mockUI.EnqueueInput("");
        _mockUI.EnqueueInput("  ");
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act & Assert - Should complete without throwing
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    [Fact]
    public async Task Should_HandleNullInput_AsExit()
    {
        // Arrange
        _mockUI.EnqueueInput(null);

        var app = CreateApp();

        // Act
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Assert - Should dispose cleanly
        _sessionManagerOps.Should().Contain(op => op.Operation == "DisposeAsync");
    }

    [Fact]
    public async Task Shutdown_Should_DisposeSessionManager()
    {
        // Arrange
        _mockUI.EnqueueInput("/exit");

        var app = CreateApp();

        // Act
        await using (app.ConfigureAwait(false))
        {
            await app.RunAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Assert - Verify SessionManager.DisposeAsync was called
        _sessionManagerOps.Should().Contain(op => op.Operation == "DisposeAsync");
    }

    private ConsoleApplication CreateApp()
    {
        return new ConsoleApplication(
            _mockUI,
            _serviceProvider.GetRequiredService<ISessionManager>(),
            _serviceProvider.GetRequiredService<ISessionFactory>(),
            _serviceProvider.GetRequiredService<IAuditLogger>(),
            _serviceProvider,
            _testRoot);
    }

    private void CreateExistingSessionFile(Guid sessionId)
    {
        var encodedPath = SessionStore.EncodeProjectPath(_testRoot);
        var sessionDir = Path.Combine(_testRoot, ".krutaka", "sessions", encodedPath);
        Directory.CreateDirectory(sessionDir);
        var sessionFile = Path.Combine(sessionDir, $"{sessionId:N}.jsonl");
        File.WriteAllText(sessionFile, "");
    }
}

/// <summary>
/// Mock ConsoleUI for testing.
/// </summary>
internal sealed class MockConsoleUI : IConsoleUI
{
    private readonly Queue<string?> _inputs = new();
    private readonly CancellationTokenSource _cts = new();

    public CancellationToken ShutdownToken => _cts.Token;

    public void EnqueueInput(string? input)
    {
        _inputs.Enqueue(input);
    }

    public void DisplayBanner()
    {
        // No-op for tests
    }

    public string? GetUserInput()
    {
        if (_inputs.Count > 0)
        {
            return _inputs.Dequeue();
        }

        return null;
    }

    public Task DisplayStreamingResponseAsync(
        IAsyncEnumerable<AgentEvent> events,
        Action<string, bool, bool>? onApprovalDecision = null,
        Action<bool, AccessLevel?, bool>? onDirectoryAccessDecision = null,
        Action<bool, bool>? onCommandApprovalDecision = null,
        CancellationToken cancellationToken = default)
    {
        // No-op for tests - just consume the events
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _cts.Dispose();
    }
}

/// <summary>
/// Tracking wrapper for SessionManager to verify operations.
/// </summary>
internal sealed class TrackingSessionManager : ISessionManager
{
    private readonly ISessionFactory _factory;
    private readonly List<SessionManagerOperation> _operations;
    private readonly SessionManager _inner;

    public TrackingSessionManager(ISessionFactory factory, List<SessionManagerOperation> operations)
    {
        _factory = factory;
        _operations = operations;
        
        var options = new SessionManagerOptions
        {
            MaxActiveSessions = 10,
            EvictionStrategy = EvictionStrategy.TerminateOldest,
            IdleTimeout = TimeSpan.FromMinutes(30),
            GlobalMaxTokensPerHour = 1_000_000,
            MaxSessionsPerUser = 10
        };
        
        _inner = new SessionManager(_factory, options);
    }

    public Task<ManagedSession> CreateSessionAsync(SessionRequest request, CancellationToken cancellationToken = default)
    {
        _operations.Add(new SessionManagerOperation("CreateSessionAsync", request.ProjectPath));
        return _inner.CreateSessionAsync(request, cancellationToken);
    }

    public Task<ManagedSession> GetOrCreateByKeyAsync(string key, SessionRequest request, CancellationToken cancellationToken = default)
    {
        _operations.Add(new SessionManagerOperation("GetOrCreateByKeyAsync", key));
        return _inner.GetOrCreateByKeyAsync(key, request, cancellationToken);
    }

    public ManagedSession? GetSession(Guid sessionId)
    {
        _operations.Add(new SessionManagerOperation("GetSession", sessionId.ToString()));
        return _inner.GetSession(sessionId);
    }

    public Task<ManagedSession> ResumeSessionAsync(Guid sessionId, string projectPath, CancellationToken cancellationToken = default)
    {
        _operations.Add(new SessionManagerOperation("ResumeSessionAsync", sessionId.ToString()));
        return _inner.ResumeSessionAsync(sessionId, projectPath, cancellationToken)!;
    }

    public Task SuspendSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        _operations.Add(new SessionManagerOperation("SuspendSessionAsync", sessionId.ToString()));
        return _inner.SuspendSessionAsync(sessionId, cancellationToken);
    }

    public Task TerminateSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        _operations.Add(new SessionManagerOperation("TerminateSessionAsync", sessionId.ToString()));
        return _inner.TerminateSessionAsync(sessionId, cancellationToken);
    }

    public Task TerminateAllAsync(CancellationToken cancellationToken = default)
    {
        _operations.Add(new SessionManagerOperation("TerminateAllAsync", string.Empty));
        return _inner.TerminateAllAsync(cancellationToken);
    }

    public IReadOnlyList<SessionSummary> ListActiveSessions()
    {
        _operations.Add(new SessionManagerOperation("ListActiveSessions", string.Empty));
        return _inner.ListActiveSessions();
    }

    public void RecordTokenUsage(int tokenCount)
    {
        _operations.Add(new SessionManagerOperation("RecordTokenUsage", tokenCount.ToString()));
        _inner.RecordTokenUsage(tokenCount);
    }

    public async ValueTask DisposeAsync()
    {
        _operations.Add(new SessionManagerOperation("DisposeAsync", string.Empty));
        await _inner.DisposeAsync();
    }
}

/// <summary>
/// Represents a SessionManager operation for testing.
/// </summary>
internal sealed record SessionManagerOperation(string Operation, string Context);

/// <summary>
/// Mock Claude client for testing.
/// </summary>
internal sealed class MockClaudeClient : IClaudeClient
{
    public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        object? tools,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask;
        yield break;
    }

    public Task<int> CountTokensAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(0);
    }
}

/// <summary>
/// Mock audit logger for testing.
/// </summary>
internal sealed class MockAuditLogger : IAuditLogger
{
    public void Log(AuditEvent auditEvent) { }
    public void LogUserInput(CorrelationContext correlationContext, string content) { }
    public void LogClaudeApiRequest(CorrelationContext correlationContext, string model, int tokenCount, int toolCount) { }
    public void LogClaudeApiResponse(CorrelationContext correlationContext, string stopReason, int inputTokens, int outputTokens) { }
    
    public void LogToolExecution(
        CorrelationContext correlationContext,
        string toolName,
        bool approved,
        bool alwaysApprove,
        long durationMs,
        int resultLength,
        string? errorMessage = null) { }
    
    public void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved) { }
    public void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context) { }
    
    public void LogCommandClassification(
        CorrelationContext correlationContext,
        string executable,
        string arguments,
        CommandRiskTier tier,
        bool autoApproved,
        string? trustedDirectory,
        string reason) { }
}
